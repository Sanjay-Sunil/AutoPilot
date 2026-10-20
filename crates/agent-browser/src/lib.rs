//! Browser control over Chrome DevTools Protocol (chromiumoxide), dedicated profile.
//! CONTRACT: keep these public signatures; implement bodies.
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageInfo { pub url: String, pub title: String }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Element {
    /// Stable index for this snapshot; pass to `click_index` / `type_index`.
    pub index: usize,
    pub role: String,
    pub text: String,
}

pub struct Browser {}

impl Browser {
    /// Lazily launch Chromium/Chrome with `profile_dir` (headful by default so the user can watch).
    pub async fn launch(_profile_dir: &Path, _headless: bool) -> anyhow::Result<Self> { todo!() }
    pub async fn navigate(&self, _url: &str) -> anyhow::Result<PageInfo> { todo!() }
    pub async fn page_text(&self, _max_chars: usize) -> anyhow::Result<String> { todo!() }
    /// Interactive elements (links, buttons, inputs) with visible text, capped at `max`.
    pub async fn elements(&self, _max: usize) -> anyhow::Result<Vec<Element>> { todo!() }
    pub async fn click_index(&self, _index: usize) -> anyhow::Result<()> { todo!() }
    pub async fn type_index(&self, _index: usize, _text: &str, _submit: bool) -> anyhow::Result<()> { todo!() }
    pub async fn screenshot_jpeg(&self, _quality: u8) -> anyhow::Result<Vec<u8>> { todo!() }
    pub async fn close(self) -> anyhow::Result<()> { todo!() }
}
