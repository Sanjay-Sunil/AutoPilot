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
    page: Page,
    handler: JoinHandle<()>,
}

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
        Ok(Self {
            inner,
            page,
            handler,
        })
    }

    async fn info(&self) -> anyhow::Result<PageInfo> {
        Ok(PageInfo {
            url: self.page.url().await?.unwrap_or_default(),
            title: self.page.get_title().await?.unwrap_or_default(),
        })
    }

    pub async fn navigate(&self, url: &str) -> anyhow::Result<PageInfo> {
        check_url(url)?;
        tokio::time::timeout(NAV_TIMEOUT, self.page.goto(url.trim()))
            .await
            .map_err(|_| anyhow::anyhow!("navigation timed out"))??;
        self.info().await
    }

    pub async fn page_text(&self, max_chars: usize) -> anyhow::Result<String> {
        let s: String = self
            .page
            .evaluate("document.body ? document.body.innerText : ''")
            .await?
            .into_value()?;
        Ok(truncate_chars(&s, max_chars))
    }

    /// Interactive elements (links, buttons, inputs) with visible text, capped at `max`.
    pub async fn elements(&self, max: usize) -> anyhow::Result<Vec<Element>> {
        let js = ELEMENTS_JS.replace("__MAX__", &max.min(10_000).to_string());
        Ok(self.page.evaluate(js).await?.into_value()?)
    }

    pub async fn click_index(&self, index: usize) -> anyhow::Result<()> {
        let el = self
            .page
            .find_element(idx_selector(index))
            .await
            .map_err(|_| anyhow::anyhow!("element {index} not found; call elements() again"))?;
        el.click().await?;
        Ok(())
    }

    pub async fn type_index(&self, index: usize, text: &str, submit: bool) -> anyhow::Result<()> {
        let js = TYPE_JS
            .replace("__IDX__", &index.to_string())
            .replace("__TEXT__", &serde_json::to_string(text)?);
        let r: String = self.page.evaluate(js).await?.into_value()?;
        match r.as_str() {
            "ok" => {}
            "missing" => anyhow::bail!("element {index} not found; call elements() again"),
            _ => anyhow::bail!("element {index} is not editable"),
        }
        if submit {
            self.page
                .find_element(idx_selector(index))
                .await?
                .press_key("Enter")
                .await?;
        }
        Ok(())
    }

    pub async fn screenshot_jpeg(&self, quality: u8) -> anyhow::Result<Vec<u8>> {
        let params = ScreenshotParams::builder()
            .format(CaptureScreenshotFormat::Jpeg)
            .quality(i64::from(quality.clamp(1, 100)))
            .build();
        Ok(self.page.screenshot(params).await?)
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
