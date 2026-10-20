//! Browser control over Chrome DevTools Protocol (chromiumoxide), dedicated profile.
//! CONTRACT: keep these public signatures; implement bodies.
//!
//! Security notes:
//! - Always uses a dedicated `user_data_dir` (never the user's main profile).
//! - Only `http`, `https`, `about:blank` and `data:` URLs may be opened; `file:`,
//!   `chrome:`, `javascript:` etc. are refused so the browser cannot be used to read
//!   local files outside the shared roots or reach browser internals.
//! - TLS certificate errors are respected (chromiumoxide ignores them by default).
//! - Text typed into fields is passed to page JS as a JSON literal, never spliced as code;
//!   password field values are never read back.
use chromiumoxide::Page;
use chromiumoxide::browser::{Browser as CdpBrowser, BrowserConfig};
use chromiumoxide::cdp::browser_protocol::page::CaptureScreenshotFormat;
use chromiumoxide::page::ScreenshotParams;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::task::JoinHandle;

/// Max time for a navigation to finish loading.
pub const NAV_TIMEOUT: Duration = Duration::from_secs(30);
/// Env var that overrides browser executable detection.
pub const BROWSER_ENV: &str = "AUTOPILOT_BROWSER";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageInfo {
    pub url: String,
    pub title: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Element {
    /// Stable index for this snapshot; pass to `click_index` / `type_index`.
    pub index: usize,
    pub role: String,
    pub text: String,
}

pub struct Browser {
    inner: CdpBrowser,
    /// Active tab; switches when a click opens a new tab or on `switch_tab`.
    page: std::sync::Mutex<Page>,
    /// Target ids in first-seen order (CDP returns pages unordered).
    order: std::sync::Mutex<Vec<String>>,
    handler: JoinHandle<()>,
}

fn tid(p: &Page) -> String {
    p.target_id().as_ref().to_string()
}

/// Max time `settle` waits for a page to stop changing after an action.
pub const SETTLE_TIMEOUT: Duration = Duration::from_secs(4);

/// Locate a Chromium-family browser: `$AUTOPILOT_BROWSER`, then `PATH`, then standard
/// install locations (Windows / macOS).
pub fn find_browser() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os(BROWSER_ENV).map(PathBuf::from) {
        if p.is_file() {
            return Some(p);
        }
    }
    const NAMES: &[&str] = &[
        "chromium",
        "google-chrome-stable",
        "google-chrome",
        "brave",
        "brave-browser",
        "chromium-browser",
    ];
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            for n in NAMES {
                let mut p = dir.join(n);
                if cfg!(windows) {
                    p.set_extension("exe");
                }
                if p.is_file() {
                    return Some(p);
                }
            }
        }
    }
    let mut candidates: Vec<PathBuf> = Vec::new();
    if cfg!(windows) {
        const REL: &[&str] = &[
            r"Google\Chrome\Application\chrome.exe",
            r"BraveSoftware\Brave-Browser\Application\brave.exe",
            r"Chromium\Application\chrome.exe",
            r"Microsoft\Edge\Application\msedge.exe",
        ];
        for var in ["PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"] {
            if let Some(base) = std::env::var_os(var) {
                candidates.extend(REL.iter().map(|r| Path::new(&base).join(r)));
            }
        }
    } else if cfg!(target_os = "macos") {
        candidates.extend(
            [
                "/Applications/Chromium.app/Contents/MacOS/Chromium",
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
            ]
            .map(PathBuf::from),
        );
    }
    candidates.into_iter().find(|p| p.is_file())
}

/// Allow only web URLs (and inert `about:blank` / `data:`).
pub fn check_url(url: &str) -> anyhow::Result<()> {
    let u = url.trim();
    let lower = u.to_ascii_lowercase();
    let ok = lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower == "about:blank"
        || lower.starts_with("data:");
    anyhow::ensure!(ok, "only http(s) URLs are allowed");
    anyhow::ensure!(!u.chars().any(|c| c.is_control()), "invalid URL");
    Ok(())
}

fn truncate_chars(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((i, _)) => s[..i].to_owned(),
        None => s.to_owned(),
    }
}

const ELEMENTS_JS: &str = r#"
(() => {
  const max = __MAX__;
  document.querySelectorAll('[data-autopilot-idx]').forEach(e => e.removeAttribute('data-autopilot-idx'));
  const sel = 'a[href], button, input:not([type=hidden]), textarea, select, [role=button], [role=link], [contenteditable]:not([contenteditable=false])';
  const out = [];
  const clean = s => (s || '').replace(/\s+/g, ' ').trim().slice(0, 80);
  for (const el of document.querySelectorAll(sel)) {
    if (out.length >= max) break;
    const r = el.getBoundingClientRect();
    if (r.width <= 0 || r.height <= 0) continue;
    const st = getComputedStyle(el);
    if (st.visibility === 'hidden' || st.display === 'none' || el.disabled) continue;
    const tag = el.tagName.toLowerCase();
    const type = (el.getAttribute('type') || '').toLowerCase();
    let role = el.getAttribute('role');
    if (!role) {
      if (tag === 'a') role = 'link';
      else if (tag === 'button') role = 'button';
      else if (tag === 'select') role = 'combobox';
      else if (tag === 'textarea' || el.isContentEditable) role = 'textbox';
      else if (tag === 'input') {
        role = ({checkbox:'checkbox', radio:'radio', submit:'button', button:'button', reset:'button',
                 password:'password', search:'searchbox', file:'file'})[type] || 'textbox';
      } else role = tag;
    }
    let text = el.getAttribute('aria-label') || el.getAttribute('placeholder');
    if (!text && tag === 'input' && ['submit', 'button', 'reset'].includes(type)) text = el.value;
    if (!text && tag !== 'input' && tag !== 'textarea') text = el.innerText;
    if (!text) text = el.getAttribute('title') || el.getAttribute('name') || el.getAttribute('alt');
    const idx = out.length;
    el.setAttribute('data-autopilot-idx', String(idx));
    out.push({ index: idx, role, text: clean(text) });
  }
  return out;
})()
"#;

const TYPE_JS: &str = r#"
(() => {
  const el = document.querySelector('[data-autopilot-idx="__IDX__"]');
  if (!el) return 'missing';
  const text = __TEXT__;
  el.scrollIntoView({ block: 'center' });
  el.focus();
  const tag = el.tagName.toLowerCase();
  if (tag === 'input' || tag === 'textarea') {
    const proto = tag === 'input' ? HTMLInputElement.prototype : HTMLTextAreaElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(proto, 'value').set;
    setter.call(el, text);
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  } else if (el.isContentEditable) {
    document.execCommand('selectAll', false, null);
    document.execCommand('insertText', false, text);
    el.dispatchEvent(new Event('input', { bubbles: true }));
  } else {
    return 'not_editable';
  }
  return 'ok';
})()
"#;

const SELECT_JS: &str = r#"
(() => {
  const el = document.querySelector('[data-autopilot-idx="__IDX__"]');
  if (!el) return { status: 'missing' };
  if (el.tagName.toLowerCase() !== 'select') return { status: 'not_select' };
  const want = String(__OPT__).toLowerCase().trim();
  const opts = Array.from(el.options);
  const txt = o => (o.text || '').toLowerCase().trim();
  const o = opts.find(o => txt(o) === want || o.value.toLowerCase() === want)
         || opts.find(o => txt(o).includes(want));
  if (!o) return { status: 'no_match', options: opts.slice(0, 30).map(o => o.text.trim()) };
  el.value = o.value;
  el.dispatchEvent(new Event('input', { bubbles: true }));
  el.dispatchEvent(new Event('change', { bubbles: true }));
  return { status: 'ok', chosen: o.text.trim() };
})()
"#;

async fn page_info(p: &Page) -> anyhow::Result<PageInfo> {
    Ok(PageInfo {
        url: p.url().await?.unwrap_or_default(),
        title: p.get_title().await?.unwrap_or_default(),
    })
}

fn idx_selector(index: usize) -> String {
    format!(r#"[data-autopilot-idx="{index}"]"#)
}

impl Browser {
    /// Lazily launch Chromium/Chrome with `profile_dir` (headful by default so the user can watch).
    pub async fn launch(profile_dir: &Path, headless: bool) -> anyhow::Result<Self> {
        let exe = find_browser().ok_or_else(|| {
            anyhow::anyhow!("no Chromium/Chrome/Brave found (set {BROWSER_ENV} to its path)")
        })?;
        std::fs::create_dir_all(profile_dir)?;
        let mut b = BrowserConfig::builder()
            .chrome_executable(exe)
            .user_data_dir(profile_dir)
            .respect_https_errors()
            .launch_timeout(Duration::from_secs(30))
            .request_timeout(Duration::from_secs(30))
            .args([
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-features=Translate,MediaRouter",
                "--password-store=basic",
            ]);
        if headless {
            b = b.new_headless_mode().window_size(1280, 800).viewport(
                chromiumoxide::handler::viewport::Viewport {
                    width: 1280,
                    height: 800,
                    ..Default::default()
                },
            );
        } else {
            b = b.with_head().window_size(1280, 900).viewport(None);
        }
        let config = b.build().map_err(|e| anyhow::anyhow!(e))?;
        let (inner, mut handler) = CdpBrowser::launch(config).await?;
        let handler = tokio::spawn(async move {
            // Drive CDP events; individual decode errors are not fatal.
            while handler.next().await.is_some() {}
        });
        let page = match inner.new_page("about:blank").await {
            Ok(p) => p,
            Err(e) => {
                handler.abort();
                return Err(e.into());
            }
        };
        // Close Chrome's own startup tab so only ours remains.
        if let Ok(pages) = inner.pages().await {
            for p in pages {
                if p.target_id() != page.target_id() {
                    let _ = p.close().await;
                }
            }
        }
        Ok(Self {
            inner,
            order: std::sync::Mutex::new(vec![tid(&page)]),
            page: std::sync::Mutex::new(page),
            handler,
        })
    }

    fn page(&self) -> Page {
        self.page.lock().unwrap().clone()
    }

    /// URL and title of the active tab.
    pub async fn info(&self) -> anyhow::Result<PageInfo> {
        page_info(&self.page()).await
    }

    pub async fn navigate(&self, url: &str) -> anyhow::Result<PageInfo> {
        check_url(url)?;
        tokio::time::timeout(NAV_TIMEOUT, self.page().goto(url.trim()))
            .await
            .map_err(|_| anyhow::anyhow!("navigation timed out"))??;
        self.info().await
    }

    pub async fn page_text(&self, max_chars: usize) -> anyhow::Result<String> {
        let s: String = self
            .page()
            .evaluate("document.body ? document.body.innerText : ''")
            .await?
            .into_value()?;
        Ok(truncate_chars(&s, max_chars))
    }

    /// Interactive elements (links, buttons, inputs) with visible text, capped at `max`.
    pub async fn elements(&self, max: usize) -> anyhow::Result<Vec<Element>> {
        let js = ELEMENTS_JS.replace("__MAX__", &max.min(10_000).to_string());
        Ok(self.page().evaluate(js).await?.into_value()?)
    }

    pub async fn click_index(&self, index: usize) -> anyhow::Result<()> {
        let el = self
            .page()
            .find_element(idx_selector(index))
            .await
            .map_err(|_| anyhow::anyhow!("element {index} not found; call elements() again"))?;
        let before = self.tab_ids().await?;
        el.click().await?;
        self.follow_new_tab(&before).await?;
        self.settle().await;
        Ok(())
    }

    pub async fn type_index(&self, index: usize, text: &str, submit: bool) -> anyhow::Result<()> {
        let js = TYPE_JS
            .replace("__IDX__", &index.to_string())
            .replace("__TEXT__", &serde_json::to_string(text)?);
        let r: String = self.page().evaluate(js).await?.into_value()?;
        match r.as_str() {
            "ok" => {}
            "missing" => anyhow::bail!("element {index} not found; call elements() again"),
            _ => anyhow::bail!("element {index} is not editable"),
        }
        if submit {
            self.page()
                .find_element(idx_selector(index))
                .await?
                .press_key("Enter")
                .await?;
            self.settle().await;
        }
        Ok(())
    }

    pub async fn screenshot_jpeg(&self, quality: u8) -> anyhow::Result<Vec<u8>> {
        let params = ScreenshotParams::builder()
            .format(CaptureScreenshotFormat::Jpeg)
            .quality(i64::from(quality.clamp(1, 100)))
            .build();
        Ok(self.page().screenshot(params).await?)
    }

    /// Wait (bounded by [`SETTLE_TIMEOUT`]) until the document is loaded and its text stops
    /// changing, so single-page apps have rendered before the next read. Never fails.
    pub async fn settle(&self) {
        let page = self.page();
        let deadline = tokio::time::Instant::now() + SETTLE_TIMEOUT;
        let mut last: Option<(String, i64)> = None;
        let mut stable = 0;
        tokio::time::sleep(Duration::from_millis(100)).await;
        while tokio::time::Instant::now() < deadline {
            let probe = "[document.readyState, document.body ? document.body.innerText.length : 0]";
            let cur: Option<(String, i64)> = match page.evaluate(probe).await {
                Ok(v) => v.into_value().ok(),
                Err(_) => None, // navigating: context destroyed
            };
            match (&cur, &last) {
                (Some(c), Some(l)) if c.0 == "complete" && c == l => stable += 1,
                _ => stable = 0,
            }
            if stable >= 2 {
                return;
            }
            last = cur;
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
    }

    async fn tab_ids(&self) -> anyhow::Result<Vec<String>> {
        Ok(self.ordered_pages().await?.iter().map(tid).collect())
    }

    /// Live pages in first-seen order; new ones are appended.
    async fn ordered_pages(&self) -> anyhow::Result<Vec<Page>> {
        let mut pages = self.inner.pages().await?;
        let mut order = self.order.lock().unwrap();
        order.retain(|id| pages.iter().any(|p| tid(p) == *id));
        for p in &pages {
            if !order.contains(&tid(p)) {
                order.push(tid(p));
            }
        }
        pages.sort_by_key(|p| order.iter().position(|id| *id == tid(p)));
        Ok(pages)
    }

    /// If an action opened a new tab, make it the active one.
    async fn follow_new_tab(&self, before: &[String]) -> anyhow::Result<()> {
        tokio::time::sleep(Duration::from_millis(150)).await;
        let pages = self.ordered_pages().await?;
        if let Some(p) = pages.into_iter().rev().find(|p| !before.contains(&tid(p))) {
            let _ = p.bring_to_front().await;
            *self.page.lock().unwrap() = p;
        }
        Ok(())
    }

    /// Open tabs in order; `.1` marks the active one.
    pub async fn tabs(&self) -> anyhow::Result<Vec<(PageInfo, bool)>> {
        let active = self.page().target_id().clone();
        let mut out = vec![];
        for p in self.ordered_pages().await? {
            let is_active = *p.target_id() == active;
            out.push((
                page_info(&p).await.unwrap_or(PageInfo {
                    url: String::new(),
                    title: String::new(),
                }),
                is_active,
            ));
        }
        Ok(out)
    }

    pub async fn switch_tab(&self, index: usize) -> anyhow::Result<PageInfo> {
        let pages = self.ordered_pages().await?;
        let p = pages
            .into_iter()
            .nth(index)
            .ok_or_else(|| anyhow::anyhow!("no tab {index}; call tabs() first"))?;
        let _ = p.bring_to_front().await;
        *self.page.lock().unwrap() = p;
        self.info().await
    }

    /// `up`/`down` scroll ~80% of the viewport; `top`/`bottom` jump. Returns the new position.
    pub async fn scroll(&self, direction: &str) -> anyhow::Result<String> {
        let action = match direction {
            "up" => "window.scrollBy(0, -window.innerHeight * 0.8)",
            "down" => "window.scrollBy(0, window.innerHeight * 0.8)",
            "top" => "window.scrollTo(0, 0)",
            "bottom" => "window.scrollTo(0, document.documentElement.scrollHeight)",
            _ => anyhow::bail!("direction must be up, down, top or bottom"),
        };
        let js = format!(
            "(() => {{ {action}; const h = document.documentElement.scrollHeight - window.innerHeight; \
             return h <= 0 ? 100 : Math.round(window.scrollY / h * 100); }})()"
        );
        let pct: i64 = self.page().evaluate(js).await?.into_value()?;
        tokio::time::sleep(Duration::from_millis(200)).await;
        Ok(format!("Scrolled {direction}; now at {pct}% of the page."))
    }

    /// History navigation (`back` = true goes back).
    pub async fn history(&self, back: bool) -> anyhow::Result<PageInfo> {
        let js = if back {
            "history.back()"
        } else {
            "history.forward()"
        };
        self.page().evaluate(js).await?;
        tokio::time::sleep(Duration::from_millis(200)).await;
        self.settle().await;
        self.info().await
    }

    /// Choose an option of a `<select>` by visible text or value (case-insensitive; exact match
    /// first, then substring). Returns the chosen option's text.
    pub async fn select_index(&self, index: usize, option: &str) -> anyhow::Result<String> {
        let js = SELECT_JS
            .replace("__IDX__", &index.to_string())
            .replace("__OPT__", &serde_json::to_string(option)?);
        let r: serde_json::Value = self.page().evaluate(js).await?.into_value()?;
        match r["status"].as_str() {
            Some("ok") => Ok(r["chosen"].as_str().unwrap_or_default().to_string()),
            Some("missing") => anyhow::bail!("element {index} not found; call elements() again"),
            Some("not_select") => anyhow::bail!("element {index} is not a dropdown"),
            _ => anyhow::bail!("no option matches `{option}`; options: {}", r["options"]),
        }
    }

    /// Press a key (`Enter`, `Escape`, `Tab`, `ArrowDown`, `PageDown`, ...) in the focused element.
    pub async fn press_key(&self, key: &str) -> anyhow::Result<()> {
        let page = self.page();
        let el = match page.find_element("*:focus").await {
            Ok(e) => e,
            Err(_) => page.find_element("body").await?,
        };
        el.press_key(key).await?;
        self.settle().await;
        Ok(())
    }

    /// Wait until the page text contains `text` (case-insensitive). Returns whether it appeared.
    pub async fn wait_for_text(&self, text: &str, timeout: Duration) -> anyhow::Result<bool> {
        let needle = text.to_lowercase();
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if self
                .page_text(200_000)
                .await
                .unwrap_or_default()
                .to_lowercase()
                .contains(&needle)
            {
                return Ok(true);
            }
            if tokio::time::Instant::now() >= deadline {
                return Ok(false);
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// Save downloads into `dir` instead of prompting.
    pub async fn set_download_dir(&self, dir: &Path) -> anyhow::Result<()> {
        use chromiumoxide::cdp::browser_protocol::browser::{
            SetDownloadBehaviorBehavior, SetDownloadBehaviorParams,
        };
        std::fs::create_dir_all(dir)?;
        let params = SetDownloadBehaviorParams::builder()
            .behavior(SetDownloadBehaviorBehavior::Allow)
            .download_path(dir.to_string_lossy().to_string())
            .build()
            .map_err(|e| anyhow::anyhow!(e))?;
        self.inner.execute(params).await?;
        Ok(())
    }

    pub async fn close(mut self) -> anyhow::Result<()> {
        let closed = self.inner.close().await;
        if closed.is_err() {
            let _ = self.inner.kill().await;
        }
        let _ = tokio::time::timeout(Duration::from_secs(5), self.inner.wait()).await;
        self.handler.abort();
        closed?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_policy() {
        for ok in [
            "https://example.com",
            "HTTP://x.y/z",
            "about:blank",
            "data:text/html,hi",
        ] {
            assert!(check_url(ok).is_ok(), "{ok}");
        }
        for bad in [
            "file:///etc/passwd",
            "chrome://settings",
            "javascript:alert(1)",
            "view-source:https://x",
            "ftp://x",
            "chrome-extension://abc/x.html",
            "https://x\ny",
            "",
        ] {
            assert!(check_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn truncation() {
        assert_eq!(truncate_chars("héllo", 2), "hé");
        assert_eq!(truncate_chars("hi", 10), "hi");
    }

    const PAGE: &str = r#"<html><head><title>T1</title></head><body>
<h1>Hello AutoPilot</h1>
<a href="data:text/html,<title>Next</title>next">Go next</a>
<button id="b" onclick="document.getElementById('out').textContent='clicked'">Press me</button>
<button style="display:none">Hidden</button>
<input id="q" placeholder="Search here" oninput="document.getElementById('echo').textContent=this.value">
<input type="password" aria-label="Password" value="s3cret">
<form onsubmit="document.title='submitted';return false"><input id="f" placeholder="Form field"></form>
<p id="out"></p><p id="echo"></p>
</body></html>"#;

    /// Runs only when a browser is installed; always headless so no window pops up.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn integration_headless() {
        if find_browser().is_none() {
            eprintln!("no browser found; skipping");
            return;
        }
        let profile = tempfile::tempdir().unwrap();
        let b = Browser::launch(profile.path(), true).await.unwrap();
        let url = format!("data:text/html,{}", urlencode(PAGE));
        let info = b.navigate(&url).await.unwrap();
        assert_eq!(info.title, "T1");
        assert!(b.navigate("file:///etc/passwd").await.is_err());

        let text = b.page_text(1000).await.unwrap();
        assert!(text.contains("Hello AutoPilot"), "{text}");
        assert_eq!(b.page_text(5).await.unwrap().chars().count(), 5);

        let els = b.elements(50).await.unwrap();
        let find = |t: &str| els.iter().find(|e| e.text == t).map(|e| e.index);
        assert!(find("Hidden").is_none(), "{els:?}");
        assert!(!els.iter().any(|e| e.text.contains("s3cret")), "{els:?}");
        let btn = find("Press me").expect("button");
        let input = find("Search here").expect("input");
        let form = find("Form field").expect("form input");
        assert_eq!(els[btn].role, "button");
        assert_eq!(els[input].role, "textbox");
        assert_eq!(find("Go next").map(|i| els[i].role.as_str()), Some("link"));
        assert_eq!(
            find("Password").map(|i| els[i].role.as_str()),
            Some("password")
        );
        assert_eq!(b.elements(2).await.unwrap().len(), 2);

        // elements(2) re-indexed; take a fresh full snapshot.
        b.elements(50).await.unwrap();
        b.click_index(btn).await.unwrap();
        b.type_index(input, "hi \"there\" </script>", false)
            .await
            .unwrap();
        let text = b.page_text(1000).await.unwrap();
        assert!(text.contains("clicked"), "{text}");
        assert!(text.contains("hi \"there\" </script>"), "{text}");
        b.type_index(form, "x", true).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(b.info().await.unwrap().title, "submitted");
        assert!(b.click_index(999).await.is_err());

        let jpg = b.screenshot_jpeg(60).await.unwrap();
        assert_eq!(&jpg[..2], &[0xFF, 0xD8], "JPEG magic");
        b.close().await.unwrap();
    }

    const PAGE2: &str = r#"<html><head><title>P2</title></head><body>
<select aria-label="Size"><option value="s">Small</option><option value="m">Medium</option><option value="l">Large one</option></select>
<p id="sel"></p>
<a href="about:blank" target="_blank">New tab</a>
<a download="note.txt" href="data:text/plain,hello%20download">Get file</a>
<input aria-label="Keys" onkeydown="if(event.key==='Escape')document.title='esc'">
<button onclick="setTimeout(()=>{document.getElementById('late').textContent='Loaded later'},400)">Load</button>
<p id="late"></p>
<div style="height:5000px">tall</div>
<script>document.querySelector('select').addEventListener('change',e=>{document.getElementById('sel').textContent='chose '+e.target.value})</script>
</body></html>"#;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn integration_navigation_tabs_downloads() {
        if find_browser().is_none() {
            eprintln!("no browser found; skipping");
            return;
        }
        let profile = tempfile::tempdir().unwrap();
        let dl = tempfile::tempdir().unwrap();
        let b = Browser::launch(profile.path(), true).await.unwrap();
        b.set_download_dir(dl.path()).await.unwrap();
        b.navigate(&format!("data:text/html,{}", urlencode(PAGE)))
            .await
            .unwrap();
        let info = b
            .navigate(&format!("data:text/html,{}", urlencode(PAGE2)))
            .await
            .unwrap();
        assert_eq!(info.title, "P2");

        let els = b.elements(50).await.unwrap();
        let find = |t: &str| {
            els.iter()
                .find(|e| e.text.starts_with(t))
                .map(|e| e.index)
                .unwrap()
        };
        assert_eq!(
            b.select_index(find("Size"), "large").await.unwrap(),
            "Large one"
        );
        assert!(b.page_text(2000).await.unwrap().contains("chose l"));
        let e = b
            .select_index(find("Size"), "huge")
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("Medium"), "{e}");
        assert!(b.select_index(find("Keys"), "x").await.is_err());

        b.click_index(find("Load")).await.unwrap();
        assert!(
            b.wait_for_text("loaded LATER", Duration::from_secs(3))
                .await
                .unwrap()
        );
        assert!(
            !b.wait_for_text("never", Duration::from_millis(300))
                .await
                .unwrap()
        );

        b.type_index(find("Keys"), "a", false).await.unwrap();
        b.press_key("Escape").await.unwrap();
        assert_eq!(b.info().await.unwrap().title, "esc");

        assert!(b.scroll("bottom").await.unwrap().contains("100%"));
        assert!(b.scroll("top").await.unwrap().contains(" 0%"));
        assert!(b.scroll("sideways").await.is_err());

        b.click_index(find("Get file")).await.unwrap();
        let file = dl.path().join("note.txt");
        for _ in 0..50 {
            if file.is_file() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "hello download");

        // A target=_blank link becomes the active tab; switching back works.
        b.click_index(find("New tab")).await.unwrap();
        let tabs = b.tabs().await.unwrap();
        assert_eq!(tabs.len(), 2, "{tabs:?}");
        assert!(tabs[1].1 && tabs[1].0.url == "about:blank", "{tabs:?}");
        assert_eq!(b.switch_tab(0).await.unwrap().title, "esc");
        assert!(b.switch_tab(9).await.is_err());

        assert_eq!(b.history(true).await.unwrap().title, "T1");
        assert_eq!(b.history(false).await.unwrap().title, "P2");
        b.close().await.unwrap();
    }

    fn urlencode(s: &str) -> String {
        let mut o = String::new();
        for b in s.bytes() {
            if b.is_ascii_alphanumeric() || b"-_.~ ".contains(&b) {
                o.push(b as char);
            } else {
                o.push_str(&format!("%{b:02X}"));
            }
        }
        o
    }
}
