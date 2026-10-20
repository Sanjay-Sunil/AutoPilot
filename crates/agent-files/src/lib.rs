//! Scoped file access: named shared roots, traversal/symlink-escape protection, chunked transfer.
//! CONTRACT: keep these public signatures; implement bodies.
use agent_protocol::{FileChunk, FileDone, FileOffer};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirEntryInfo {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified_ms: u64,
}

/// Named roots, e.g. ("Documents", ~/Documents). Paths are addressed as "Documents/sub/file.txt".
#[derive(Debug, Clone)]
pub struct SharedRoots { pub roots: Vec<(String, PathBuf)> }

impl SharedRoots {
    pub fn new(_roots: Vec<(String, PathBuf)>) -> Self { todo!() }
    pub fn names(&self) -> Vec<String> { todo!() }
    /// Resolve a rooted relative path to a canonical absolute path inside its root.
    /// Rejects "..", absolute paths, NUL, unknown roots and symlinks escaping the root.
    /// The target need not exist when `must_exist` is false (parent must, and must be inside).
    pub fn resolve(&self, _rel: &str, _must_exist: bool) -> anyhow::Result<PathBuf> { todo!() }
    pub fn list(&self, _rel: &str) -> anyhow::Result<Vec<DirEntryInfo>> { todo!() }
    pub fn read_text(&self, _rel: &str, _max_bytes: usize) -> anyhow::Result<String> { todo!() }
    pub fn write_text(&self, _rel: &str, _content: &str) -> anyhow::Result<()> { todo!() }
    /// Case-insensitive name search under a rooted dir, max depth, max results.
    pub fn search(&self, _rel: &str, _query: &str, _max_results: usize) -> anyhow::Result<Vec<String>> { todo!() }
}

/// Sends a file as FILE_CHUNK_SIZE base64 chunks.
pub struct FileSender {}
impl FileSender {
    pub fn open(_path: &Path, _transfer_id: uuid::Uuid) -> anyhow::Result<(Self, FileOffer)> { todo!() }
    pub fn seek(&mut self, _offset: u64) -> anyhow::Result<()> { todo!() }
    pub fn next_chunk(&mut self) -> anyhow::Result<Option<FileChunk>> { todo!() }
}

/// Receives into `inbox/<name>.part`, verifies SHA-256 at the end, renames atomically.
pub struct FileReceiver {}
impl FileReceiver {
    pub fn new(_inbox: &Path, _offer: &FileOffer, _max_size: u64) -> anyhow::Result<Self> { todo!() }
    /// Offset to resume from (size of existing .part file).
    pub fn offset(&self) -> u64 { todo!() }
    pub fn write_chunk(&mut self, _c: &FileChunk) -> anyhow::Result<()> { todo!() }
    pub fn finish(self) -> anyhow::Result<FileDone> { todo!() }
}

