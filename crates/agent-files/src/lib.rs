//! Scoped file access: named shared roots, traversal/symlink-escape protection, chunked transfer.
//! CONTRACT: keep these public signatures; implement bodies.
//!
//! Security model:
//! - Paths are addressed as `<RootName>/<relative path>`; anything outside a configured root
//!   is invisible. Absolute paths, `..`, NUL, backslashes, drive/ADS colons and unknown roots
//!   are rejected before touching the filesystem.
//! - Resolved paths are canonicalized and must stay under the canonical root, so symlinks that
//!   point outside a root are refused. Final opens use `O_NOFOLLOW` on Unix to narrow the
//!   symlink-swap TOCTOU window.
//! - Received files land in the inbox under a sanitized basename, are size-capped, written
//!   strictly in order and only renamed into place after the SHA-256 matches.
use agent_protocol::{FILE_CHUNK_SIZE, FileChunk, FileDone, FileOffer};
use anyhow::{Context, anyhow, bail, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::time::UNIX_EPOCH;

/// Max directory depth walked by [`SharedRoots::search`].
pub const SEARCH_MAX_DEPTH: usize = 6;
/// Bytes inspected for NUL when deciding whether a file is binary.
pub const BINARY_SNIFF_BYTES: usize = 8 * 1024;
/// Max length (bytes) of a sanitized received file name.
pub const MAX_NAME_BYTES: usize = 200;

const SKIP_DIRS: &[&str] = &["node_modules", ".git", "target"];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirEntryInfo {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified_ms: u64,
}

/// Named roots, e.g. ("Documents", ~/Documents). Paths are addressed as "Documents/sub/file.txt".
#[derive(Debug, Clone)]
pub struct SharedRoots {
    pub roots: Vec<(String, PathBuf)>,
}

fn modified_ms(md: &fs::Metadata) -> u64 {
    md.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn is_root_level(rel: &str) -> bool {
    rel.trim().is_empty() || rel.trim() == "/"
}

fn open_nofollow_read(p: &Path) -> std::io::Result<File> {
    let mut o = OpenOptions::new();
    o.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(libc::O_NOFOLLOW);
    }
    o.open(p)
}

fn open_nofollow_write(p: &Path, create_new: bool) -> std::io::Result<File> {
    let mut o = OpenOptions::new();
    o.write(true).read(true);
    if create_new {
        o.create_new(true);
    } else {
        o.create(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(libc::O_NOFOLLOW);
        o.mode(0o600);
    }
    o.open(p)
}

/// Splits and validates a rooted path into (root name, sub components).
fn split_rel(rel: &str) -> anyhow::Result<(&str, Vec<&str>)> {
    ensure!(!rel.contains('\0'), "path contains NUL");
    ensure!(!rel.contains('\\'), "backslashes are not allowed in paths");
    ensure!(
        !rel.contains(':') || !cfg!(windows),
        "':' is not allowed in paths"
    );
    ensure!(
        !rel.starts_with('/') && !Path::new(rel).is_absolute(),
        "absolute paths are not allowed"
    );
    ensure!(
        !rel.chars().any(|c| c.is_control()),
        "path contains control characters"
    );
    let mut parts = Vec::new();
    for p in rel.split('/') {
        match p {
            "" | "." => continue,
            ".." => bail!("'..' is not allowed in paths"),
            _ => parts.push(p),
        }
    }
    ensure!(!parts.is_empty(), "empty path");
    // Double-check with the platform parser (catches prefixes etc.).
    for p in &parts[1..] {
        let mut comps = Path::new(p).components();
        ensure!(
            matches!(comps.next(), Some(Component::Normal(_))) && comps.next().is_none(),
            "invalid path component"
        );
    }
    let root = parts.remove(0);
    Ok((root, parts))
}

impl SharedRoots {
    pub fn new(roots: Vec<(String, PathBuf)>) -> Self {
        Self { roots }
    }

    pub fn names(&self) -> Vec<String> {
        self.roots.iter().map(|(n, _)| n.clone()).collect()
    }

    fn canonical_root(&self, name: &str) -> anyhow::Result<PathBuf> {
        let (_, p) = self
            .roots
            .iter()
            .find(|(n, _)| n == name)
            .ok_or_else(|| anyhow!("unknown shared root"))?;
        fs::canonicalize(p).with_context(|| format!("shared root '{name}' is unavailable"))
    }

    /// Resolve a rooted relative path to a canonical absolute path inside its root.
    /// Rejects "..", absolute paths, NUL, unknown roots and symlinks escaping the root.
    /// The target need not exist when `must_exist` is false (parent must, and must be inside).
    pub fn resolve(&self, rel: &str, must_exist: bool) -> anyhow::Result<PathBuf> {
        let (root_name, parts) = split_rel(rel)?;
        let root = self.canonical_root(root_name)?;
        let mut joined = root.clone();
        joined.extend(&parts);

        let inside = |p: &Path| -> anyhow::Result<()> {
            ensure!(p.starts_with(&root), "path escapes its shared root");
            Ok(())
        };

        match fs::symlink_metadata(&joined) {
            Ok(_) => {
                // Exists (possibly as a symlink): canonicalize fully; dangling links error out.
                let c = fs::canonicalize(&joined).context("cannot resolve path")?;
                inside(&c)?;
                Ok(c)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && !must_exist => {
                let (Some(parent), Some(file)) = (joined.parent(), joined.file_name()) else {
                    bail!("invalid path");
                };
                let cp = fs::canonicalize(parent).context("parent directory does not exist")?;
                inside(&cp)?;
                ensure!(cp.is_dir(), "parent is not a directory");
                Ok(cp.join(file))
            }
            Err(_) => bail!("path not found"),
        }
    }

    /// Maps a canonical path back to its "Root/sub/path" display form.
    fn to_rooted(&self, root_name: &str, root: &Path, p: &Path) -> Option<String> {
        let sub = p.strip_prefix(root).ok()?;
        let mut s = root_name.to_owned();
        for c in sub.components() {
            s.push('/');
            s.push_str(&c.as_os_str().to_string_lossy());
        }
        Some(s)
    }

    pub fn list(&self, rel: &str) -> anyhow::Result<Vec<DirEntryInfo>> {
        if is_root_level(rel) {
            return Ok(self
                .roots
                .iter()
                .map(|(name, p)| {
                    let md = fs::metadata(p).ok();
                    DirEntryInfo {
                        name: name.clone(),
                        is_dir: true,
                        size: 0,
                        modified_ms: md.as_ref().map(modified_ms).unwrap_or(0),
                    }
                })
                .collect());
        }
        let (root_name, _) = split_rel(rel)?;
        let root = self.canonical_root(root_name)?;
        let dir = self.resolve(rel, true)?;
        ensure!(dir.is_dir(), "not a directory");
        let mut out = Vec::new();
        for ent in fs::read_dir(&dir)? {
            let ent = ent?;
            let name = ent.file_name().to_string_lossy().into_owned();
            let Ok(lmd) = ent.path().symlink_metadata() else {
                continue;
            };
            // Follow symlinks only if they stay inside the root; otherwise show the link
            // itself (as a non-directory, size 0) without revealing anything about its target.
            let md = if lmd.file_type().is_symlink() {
                match fs::canonicalize(ent.path()) {
                    Ok(t) if t.starts_with(&root) => fs::metadata(&t).ok(),
                    _ => None,
                }
            } else {
                Some(lmd)
            };
            out.push(match md {
                Some(md) => DirEntryInfo {
                    name,
                    is_dir: md.is_dir(),
                    size: if md.is_dir() { 0 } else { md.len() },
                    modified_ms: modified_ms(&md),
                },
                None => DirEntryInfo {
                    name,
                    is_dir: false,
                    size: 0,
                    modified_ms: 0,
                },
            });
        }
        out.sort_by(|a, b| {
            b.is_dir
                .cmp(&a.is_dir)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
                .then_with(|| a.name.cmp(&b.name))
        });
        Ok(out)
    }

    /// Reads at most `max_bytes` (lossy UTF-8; truncated if longer). Rejects binary files.
    pub fn read_text(&self, rel: &str, max_bytes: usize) -> anyhow::Result<String> {
        let p = self.resolve(rel, true)?;
        let f = open_nofollow_read(&p).context("cannot open file")?;
        ensure!(f.metadata()?.is_file(), "not a regular file");
        let mut buf = Vec::with_capacity(max_bytes.min(1 << 20));
        f.take(max_bytes as u64).read_to_end(&mut buf)?;
        let sniff = &buf[..buf.len().min(BINARY_SNIFF_BYTES)];
        ensure!(!sniff.contains(&0), "file looks binary");
        Ok(String::from_utf8_lossy(&buf).into_owned())
    }

    /// Atomic write: temp file in the same directory, fsync, rename over the target.
    pub fn write_text(&self, rel: &str, content: &str) -> anyhow::Result<()> {
        let target = self.resolve(rel, false)?;
        if let Ok(md) = fs::symlink_metadata(&target) {
            ensure!(md.is_file(), "target is not a regular file");
        }
        let dir = target.parent().ok_or_else(|| anyhow!("invalid path"))?;
        let fname = target
            .file_name()
            .ok_or_else(|| anyhow!("invalid path"))?
            .to_string_lossy();
        let tmp = dir.join(format!(".{fname}.{}.tmp", uuid::Uuid::new_v4().simple()));
        let res = (|| -> anyhow::Result<()> {
            let mut f = open_nofollow_write(&tmp, true)?;
            f.write_all(content.as_bytes())?;
            f.sync_all()?;
            drop(f);
            fs::rename(&tmp, &target)?;
            Ok(())
        })();
        if res.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        res
    }

    /// Case-insensitive name search under a rooted dir, max depth, max results.
    pub fn search(
        &self,
        rel: &str,
        query: &str,
        max_results: usize,
    ) -> anyhow::Result<Vec<String>> {
        let q = query.trim().to_lowercase();
        ensure!(!q.is_empty(), "empty search query");
        let bases: Vec<(String, PathBuf, PathBuf)> = if is_root_level(rel) {
            self.roots
                .iter()
                .filter_map(|(n, _)| {
                    let r = self.canonical_root(n).ok()?;
                    Some((n.clone(), r.clone(), r))
                })
                .collect()
        } else {
            let (root_name, _) = split_rel(rel)?;
            let root = self.canonical_root(root_name)?;
            let base = self.resolve(rel, true)?;
            ensure!(base.is_dir(), "not a directory");
            vec![(root_name.to_owned(), root, base)]
        };
        let mut out = Vec::new();
        for (name, root, base) in bases {
            let walker = walkdir::WalkDir::new(&base)
                .max_depth(SEARCH_MAX_DEPTH)
                .follow_links(false)
                .into_iter()
                .filter_entry(|e| {
                    if e.depth() == 0 {
                        return true;
                    }
                    let n = e.file_name().to_string_lossy();
                    !(n.starts_with('.') || (e.file_type().is_dir() && SKIP_DIRS.contains(&&*n)))
                });
            for e in walker.filter_map(Result::ok) {
                if out.len() >= max_results {
                    return Ok(out);
                }
                if e.depth() == 0 {
                    continue;
                }
                if e.file_name().to_string_lossy().to_lowercase().contains(&q) {
                    out.extend(self.to_rooted(&name, &root, e.path()));
                }
            }
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Transfers
// ---------------------------------------------------------------------------

fn sha256_reader<R: Read>(mut r: R, h: &mut Sha256) -> std::io::Result<u64> {
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            return Ok(total);
        }
        h.update(&buf[..n]);
        total += n as u64;
    }
}

/// Sends a file as FILE_CHUNK_SIZE base64 chunks.
pub struct FileSender {
    file: BufReader<File>,
    transfer_id: uuid::Uuid,
    offset: u64,
    size: u64,
}

impl FileSender {
    /// `path` must already be resolved through [`SharedRoots::resolve`].
    pub fn open(path: &Path, transfer_id: uuid::Uuid) -> anyhow::Result<(Self, FileOffer)> {
        let f = open_nofollow_read(path).context("cannot open file")?;
        let md = f.metadata()?;
        ensure!(md.is_file(), "not a regular file");
        let mut reader = BufReader::with_capacity(FILE_CHUNK_SIZE * 2, f);
        let mut h = Sha256::new();
        let size = sha256_reader(&mut reader, &mut h)?;
        reader.seek(SeekFrom::Start(0))?;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "file".into());
        let offer = FileOffer {
            transfer_id,
            name,
            size,
            sha256: hex::encode(h.finalize()),
        };
        Ok((
            Self {
                file: reader,
                transfer_id,
                offset: 0,
                size,
            },
            offer,
        ))
    }

    pub fn seek(&mut self, offset: u64) -> anyhow::Result<()> {
        ensure!(offset <= self.size, "seek past end of file");
        self.file.seek(SeekFrom::Start(offset))?;
        self.offset = offset;
        Ok(())
    }

    pub fn next_chunk(&mut self) -> anyhow::Result<Option<FileChunk>> {
        let mut buf = vec![0u8; FILE_CHUNK_SIZE];
        let mut n = 0;
        while n < buf.len() {
            let r = self.file.read(&mut buf[n..])?;
            if r == 0 {
                break;
            }
            n += r;
        }
        if n == 0 {
            return Ok(None);
        }
        let c = FileChunk {
            transfer_id: self.transfer_id,
            offset: self.offset,
            data_b64: B64.encode(&buf[..n]),
        };
        self.offset += n as u64;
        Ok(Some(c))
    }
}

/// Windows device names that must never be used as file names.
const RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

fn truncate_bytes(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut cut = max;
    while !s.is_char_boundary(cut) {
        cut -= 1;
    }
    &s[..cut]
}

/// Basename only, no control or path-special characters, no leading dots, at most
/// [`MAX_NAME_BYTES`] bytes (extension preserved), never empty or a Windows device name.
pub fn sanitize_file_name(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or("");
    let cleaned: String = base
        .chars()
        .filter(|c| !c.is_control() && !matches!(c, ':' | '*' | '?' | '"' | '<' | '>' | '|'))
        .collect();
    let cleaned = cleaned
        .trim()
        .trim_start_matches('.')
        .trim_end_matches(['.', ' '])
        .trim_start();
    let mut s = if cleaned.is_empty() {
        "file".to_owned()
    } else {
        cleaned.to_owned()
    };
    let stem_upper = s.split('.').next().unwrap_or("").to_ascii_uppercase();
    if RESERVED.contains(&stem_upper.as_str()) {
        s = format!("_{s}");
    }
    if s.len() > MAX_NAME_BYTES {
        let (stem, ext) = split_ext(&s);
        s = if !ext.is_empty() && ext.len() <= 16 {
            format!(
                "{}{}",
                truncate_bytes(stem, MAX_NAME_BYTES - ext.len()),
                ext
            )
        } else {
            truncate_bytes(&s, MAX_NAME_BYTES).to_owned()
        };
    }
    s
}

/// ("report", ".pdf"); dotless names give ("name", "").
fn split_ext(s: &str) -> (&str, &str) {
    match s.rfind('.') {
        Some(i) if i > 0 => (&s[..i], &s[i..]),
        _ => (s, ""),
    }
}

/// File types that should require explicit approval when received (spec §9.2).
pub fn is_executable_name(name: &str) -> bool {
    const EXT: &[&str] = &[
        "exe", "msi", "bat", "cmd", "com", "scr", "ps1", "vbs", "js", "jse", "wsf", "hta", "cpl",
        "lnk", "jar", "sh", "bash", "zsh", "run", "bin", "appimage", "deb", "rpm", "dmg", "pkg",
        "app", "command", "py", "pl", "rb", "desktop", "reg", "dll", "so",
    ];
    let (_, ext) = split_ext(name);
    let ext = ext.trim_start_matches('.').to_ascii_lowercase();
    EXT.contains(&ext.as_str())
}

/// Receives into `inbox/<name>.part`, verifies SHA-256 at the end, renames atomically.
pub struct FileReceiver {
    inbox: PathBuf,
    name: String,
    part: PathBuf,
    file: File,
    offer: FileOffer,
    offset: u64,
    hasher: Sha256,
}

impl FileReceiver {
    pub fn new(inbox: &Path, offer: &FileOffer, max_size: u64) -> anyhow::Result<Self> {
        ensure!(
            offer.size <= max_size,
            "file too large ({} > {max_size} bytes)",
            offer.size
        );
        ensure!(
            offer.sha256.len() == 64 && offer.sha256.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid sha256 in offer"
        );
        fs::create_dir_all(inbox)?;
        let inbox = fs::canonicalize(inbox)?;
        let name = sanitize_file_name(&offer.name);
        let part = inbox.join(format!("{name}.part"));
        if let Ok(md) = fs::symlink_metadata(&part) {
            ensure!(md.is_file(), "existing .part is not a regular file");
        }
        let mut file = open_nofollow_write(&part, false)?;
        let mut existing = file.metadata()?.len();
        if existing > offer.size {
            file.set_len(0)?;
            existing = 0;
        }
        let mut hasher = Sha256::new();
        file.seek(SeekFrom::Start(0))?;
        let hashed = sha256_reader((&mut file).take(existing), &mut hasher)?;
        ensure!(hashed == existing, "short read on .part file");
        file.seek(SeekFrom::Start(existing))?;
        Ok(Self {
            inbox,
            name,
            part,
            file,
            offer: offer.clone(),
            offset: existing,
            hasher,
        })
    }

    /// Offset to resume from (size of existing .part file).
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Sanitized target file name (before de-duplication).
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn write_chunk(&mut self, c: &FileChunk) -> anyhow::Result<()> {
        ensure!(c.transfer_id == self.offer.transfer_id, "wrong transfer id");
        ensure!(
            c.offset == self.offset,
            "out-of-order chunk: got offset {}, expected {}",
            c.offset,
            self.offset
        );
        // Cheap pre-check before decoding to bound memory use.
        ensure!(
            c.data_b64.len() <= FILE_CHUNK_SIZE.div_ceil(3) * 4 + 4,
            "chunk too large"
        );
        let data = B64
            .decode(c.data_b64.as_bytes())
            .context("invalid base64")?;
        ensure!(data.len() <= FILE_CHUNK_SIZE, "chunk too large");
        ensure!(
            self.offset + data.len() as u64 <= self.offer.size,
            "chunk exceeds announced size"
        );
        self.file.write_all(&data)?;
        self.hasher.update(&data);
        self.offset += data.len() as u64;
        Ok(())
    }

    pub fn finish(self) -> anyhow::Result<FileDone> {
        self.finish_with_path().map(|(d, _)| d)
    }

    /// Like [`finish`](Self::finish) but also returns the final path on success.
    pub fn finish_with_path(self) -> anyhow::Result<(FileDone, Option<PathBuf>)> {
        let Self {
            inbox,
            name,
            part,
            file,
            offer,
            offset,
            hasher,
        } = self;
        file.sync_all()?;
        drop(file);
        let sha = hex::encode(hasher.finalize());
        let fail = |reason: String| -> anyhow::Result<(FileDone, Option<PathBuf>)> {
            let _ = fs::remove_file(&part);
            Ok((
                FileDone {
                    transfer_id: offer.transfer_id,
                    ok: false,
                    sha256: sha.clone(),
                    reason: Some(reason),
                },
                None,
            ))
        };
        if offset != offer.size {
            return fail(format!("incomplete: {offset} of {} bytes", offer.size));
        }
        if !sha.eq_ignore_ascii_case(&offer.sha256) {
            return fail("sha256 mismatch".into());
        }
        let dest = unique_dest(&inbox, &name)?;
        fs::rename(&part, &dest)?;
        Ok((
            FileDone {
                transfer_id: offer.transfer_id,
                ok: true,
                sha256: sha,
                reason: None,
            },
            Some(dest),
        ))
    }
}

/// `name`, then `stem (1).ext`, `stem (2).ext`, ...
fn unique_dest(dir: &Path, name: &str) -> anyhow::Result<PathBuf> {
    let p = dir.join(name);
    if fs::symlink_metadata(&p).is_err() {
        return Ok(p);
    }
    let (stem, ext) = split_ext(name);
    for i in 1..10_000 {
        let p = dir.join(format!("{stem} ({i}){ext}"));
        if fs::symlink_metadata(&p).is_err() {
            return Ok(p);
        }
    }
    bail!("too many files named {name}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup() -> (TempDir, SharedRoots) {
        let t = tempfile::tempdir().unwrap();
        let docs = t.path().join("docs");
        fs::create_dir_all(docs.join("sub/deeper")).unwrap();
        fs::create_dir_all(docs.join(".hidden")).unwrap();
        fs::create_dir_all(docs.join("node_modules/pkg")).unwrap();
        fs::write(docs.join("a.txt"), "hello").unwrap();
        fs::write(docs.join("B.md"), "# hi").unwrap();
        fs::write(docs.join("sub/Report.TXT"), "r").unwrap();
        fs::write(docs.join("sub/deeper/report-2.txt"), "r2").unwrap();
        fs::write(docs.join(".hidden/report.txt"), "x").unwrap();
        fs::write(docs.join("node_modules/pkg/report.js"), "x").unwrap();
        fs::write(docs.join("bin.dat"), [1u8, 0, 2, 3]).unwrap();
        fs::write(t.path().join("secret.txt"), "top secret").unwrap();
        let roots = SharedRoots::new(vec![("Documents".into(), docs)]);
        (t, roots)
    }

    #[test]
    fn rejects_traversal_and_bad_paths() {
        let (_t, r) = setup();
        for bad in [
            "../secret.txt",
            "Documents/../secret.txt",
            "Documents/../../etc/passwd",
            "Documents/sub/../../secret.txt",
            "/etc/passwd",
            "/Documents/a.txt",
            "Documents/a.txt\0",
            "Documents\\..\\secret.txt",
            "Unknown/a.txt",
            "Documents/a\n.txt",
            "",
        ] {
            assert!(r.resolve(bad, false).is_err(), "accepted {bad:?}");
            assert!(r.read_text(bad, 100).is_err(), "read {bad:?}");
        }
        assert!(r.write_text("Documents/../evil.txt", "x").is_err());
        assert!(!_t.path().join("evil.txt").exists());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_escape() {
        let (t, r) = setup();
        let docs = t.path().join("docs");
        std::os::unix::fs::symlink("/etc", docs.join("etc")).unwrap();
        std::os::unix::fs::symlink(t.path().join("secret.txt"), docs.join("s.txt")).unwrap();
        std::os::unix::fs::symlink(t.path().join("nowhere"), docs.join("dangling")).unwrap();
        std::os::unix::fs::symlink(docs.join("a.txt"), docs.join("inside.txt")).unwrap();
        assert!(r.resolve("Documents/etc/passwd", true).is_err());
        assert!(r.read_text("Documents/etc/passwd", 100).is_err());
        assert!(r.read_text("Documents/s.txt", 100).is_err());
        assert!(r.write_text("Documents/s.txt", "pwn").is_err());
        assert!(r.write_text("Documents/etc/new.txt", "pwn").is_err());
        assert!(r.write_text("Documents/dangling", "pwn").is_err());
        assert!(!t.path().join("nowhere").exists());
        assert_eq!(
            fs::read_to_string(t.path().join("secret.txt")).unwrap(),
            "top secret"
        );
        assert!(r.list("Documents/etc").is_err());
        // Symlinks that stay inside are fine.
        assert_eq!(r.read_text("Documents/inside.txt", 100).unwrap(), "hello");
        // Escaping links are listed but not followed.
        let l = r.list("Documents").unwrap();
        let e = l.iter().find(|e| e.name == "etc").unwrap();
        assert!(!e.is_dir && e.size == 0);
        assert!(r.search("", "passwd", 10).unwrap().is_empty());
    }

    #[test]
    fn root_level_and_listing() {
        let (_t, r) = setup();
        assert_eq!(r.names(), vec!["Documents"]);
        for p in ["", "/"] {
            let l = r.list(p).unwrap();
            assert_eq!(l.len(), 1);
            assert!(l[0].is_dir && l[0].name == "Documents");
        }
        let l = r.list("Documents").unwrap();
        let names: Vec<_> = l.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(
            names,
            [".hidden", "node_modules", "sub", "a.txt", "B.md", "bin.dat"]
        );
        assert_eq!(l[3].size, 5);
        assert!(l[3].modified_ms > 0);
        assert!(r.list("Documents/a.txt").is_err());
    }

    #[test]
    fn read_text_caps_and_rejects_binary() {
        let (_t, r) = setup();
        assert_eq!(r.read_text("Documents/a.txt", 100).unwrap(), "hello");
        assert_eq!(r.read_text("Documents/a.txt", 3).unwrap(), "hel");
        assert!(r.read_text("Documents/bin.dat", 100).is_err());
        assert!(r.read_text("Documents/sub", 100).is_err());
    }

    #[test]
    fn write_text_atomic() {
        let (t, r) = setup();
        r.write_text("Documents/sub/new.txt", "fresh").unwrap();
        assert_eq!(r.read_text("Documents/sub/new.txt", 100).unwrap(), "fresh");
        r.write_text("Documents/a.txt", "replaced").unwrap();
        assert_eq!(r.read_text("Documents/a.txt", 100).unwrap(), "replaced");
        assert!(r.write_text("Documents/missing/x.txt", "x").is_err());
        assert!(r.write_text("Documents/sub", "x").is_err());
        let leftovers: Vec<_> = fs::read_dir(t.path().join("docs/sub"))
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn search_skips_hidden_and_caps() {
        let (_t, r) = setup();
        let mut res = r.search("Documents", "REPORT", 10).unwrap();
        res.sort();
        assert_eq!(
            res,
            [
                "Documents/sub/Report.TXT",
                "Documents/sub/deeper/report-2.txt"
            ]
        );
        assert_eq!(r.search("", "report", 1).unwrap().len(), 1);
        assert_eq!(
            r.search("Documents/sub/deeper", "report", 10).unwrap(),
            ["Documents/sub/deeper/report-2.txt"]
        );
        assert!(r.search("Documents/../", "x", 10).is_err());
        assert!(r.search("Documents", "", 10).is_err());
    }

    #[test]
    fn sanitize_names() {
        assert_eq!(sanitize_file_name("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_file_name("..\\..\\win.ini"), "win.ini");
        assert_eq!(sanitize_file_name(".bashrc"), "bashrc");
        assert_eq!(sanitize_file_name("..."), "file");
        assert_eq!(sanitize_file_name(""), "file");
        assert_eq!(sanitize_file_name("a\u{0}b\nc\u{7f}.txt"), "abc.txt");
        assert_eq!(sanitize_file_name("CON.txt"), "_CON.txt");
        assert_eq!(sanitize_file_name("résumé 文档.pdf"), "résumé 文档.pdf");
        let long = "文".repeat(300) + ".pdf";
        let s = sanitize_file_name(&long);
        assert!(s.len() <= MAX_NAME_BYTES && s.ends_with(".pdf"));
        assert!(is_executable_name("setup.EXE") && !is_executable_name("photo.jpg"));
    }

    fn send_all(src: &Path, inbox: &Path, max: u64) -> anyhow::Result<(FileDone, Option<PathBuf>)> {
        let id = uuid::Uuid::new_v4();
        let (mut s, offer) = FileSender::open(src, id)?;
        let mut rx = FileReceiver::new(inbox, &offer, max)?;
        s.seek(rx.offset())?;
        while let Some(c) = s.next_chunk()? {
            rx.write_chunk(&c)?;
        }
        rx.finish_with_path()
    }

    fn big_file(dir: &Path, name: &str, len: usize) -> PathBuf {
        let p = dir.join(name);
        let data: Vec<u8> = (0..len).map(|i| (i * 31 % 251) as u8).collect();
        fs::write(&p, data).unwrap();
        p
    }

    #[test]
    fn transfer_roundtrip_and_dedupe() {
        let t = tempfile::tempdir().unwrap();
        let inbox = t.path().join("inbox");
        let src = big_file(t.path(), "résumé 文档.bin", FILE_CHUNK_SIZE * 3 + 17);
        let (done, path) = send_all(&src, &inbox, 1 << 30).unwrap();
        assert!(done.ok, "{:?}", done.reason);
        let path = path.unwrap();
        assert_eq!(path.file_name().unwrap(), "résumé 文档.bin");
        assert_eq!(fs::read(&path).unwrap(), fs::read(&src).unwrap());
        let (done, path) = send_all(&src, &inbox, 1 << 30).unwrap();
        assert!(done.ok);
        assert_eq!(path.unwrap().file_name().unwrap(), "résumé 文档 (1).bin");
        // Empty file.
        let empty = big_file(t.path(), "empty", 0);
        assert!(send_all(&empty, &inbox, 10).unwrap().0.ok);
    }

    #[test]
    fn transfer_rejects_oversize() {
        let t = tempfile::tempdir().unwrap();
        let src = big_file(t.path(), "x.bin", 1000);
        assert!(send_all(&src, &t.path().join("inbox"), 999).is_err());
        // A lying sender that announces a small size but sends more.
        let (mut s, mut offer) = FileSender::open(&src, uuid::Uuid::new_v4()).unwrap();
        offer.size = 10;
        let mut rx = FileReceiver::new(&t.path().join("inbox"), &offer, 100).unwrap();
        let c = s.next_chunk().unwrap().unwrap();
        assert!(rx.write_chunk(&c).is_err());
    }

    #[test]
    fn transfer_wrong_hash_deletes_part() {
        let t = tempfile::tempdir().unwrap();
        let inbox = t.path().join("inbox");
        let src = big_file(t.path(), "x.bin", 5000);
        let (mut s, mut offer) = FileSender::open(&src, uuid::Uuid::new_v4()).unwrap();
        offer.sha256 = "0".repeat(64);
        let mut rx = FileReceiver::new(&inbox, &offer, 1 << 20).unwrap();
        while let Some(c) = s.next_chunk().unwrap() {
            rx.write_chunk(&c).unwrap();
        }
        let done = rx.finish().unwrap();
        assert!(!done.ok);
        assert_eq!(done.reason.as_deref(), Some("sha256 mismatch"));
        assert_eq!(fs::read_dir(&inbox).unwrap().count(), 0);
    }

    #[test]
    fn transfer_rejects_out_of_order_and_foreign_chunks() {
        let t = tempfile::tempdir().unwrap();
        let src = big_file(t.path(), "x.bin", FILE_CHUNK_SIZE * 2);
        let (mut s, offer) = FileSender::open(&src, uuid::Uuid::new_v4()).unwrap();
        let mut rx = FileReceiver::new(&t.path().join("inbox"), &offer, 1 << 20).unwrap();
        let c0 = s.next_chunk().unwrap().unwrap();
        let c1 = s.next_chunk().unwrap().unwrap();
        assert!(rx.write_chunk(&c1).is_err());
        let mut foreign = c0.clone();
        foreign.transfer_id = uuid::Uuid::new_v4();
        assert!(rx.write_chunk(&foreign).is_err());
        rx.write_chunk(&c0).unwrap();
        assert!(rx.write_chunk(&c0).is_err(), "replayed chunk");
        rx.write_chunk(&c1).unwrap();
        assert!(rx.finish().unwrap().ok);
    }

    #[test]
    fn transfer_resume_after_partial() {
        let t = tempfile::tempdir().unwrap();
        let inbox = t.path().join("inbox");
        let src = big_file(t.path(), "movie.mp4", FILE_CHUNK_SIZE * 4 + 5);
        let id = uuid::Uuid::new_v4();
        let (mut s, offer) = FileSender::open(&src, id).unwrap();
        {
            let mut rx = FileReceiver::new(&inbox, &offer, 1 << 30).unwrap();
            assert_eq!(rx.offset(), 0);
            for _ in 0..2 {
                rx.write_chunk(&s.next_chunk().unwrap().unwrap()).unwrap();
            }
            // Connection drops: receiver dropped without finish.
        }
        assert!(inbox.join("movie.mp4.part").exists());
        let (mut s, offer) = FileSender::open(&src, id).unwrap();
        let mut rx = FileReceiver::new(&inbox, &offer, 1 << 30).unwrap();
        assert_eq!(rx.offset(), (FILE_CHUNK_SIZE * 2) as u64);
        s.seek(rx.offset()).unwrap();
        while let Some(c) = s.next_chunk().unwrap() {
            rx.write_chunk(&c).unwrap();
        }
        let (done, path) = rx.finish_with_path().unwrap();
        assert!(done.ok, "{:?}", done.reason);
        assert_eq!(fs::read(path.unwrap()).unwrap(), fs::read(&src).unwrap());
        assert!(!inbox.join("movie.mp4.part").exists());
    }

    #[test]
    fn incomplete_finish_fails() {
        let t = tempfile::tempdir().unwrap();
        let src = big_file(t.path(), "x.bin", FILE_CHUNK_SIZE + 1);
        let (mut s, offer) = FileSender::open(&src, uuid::Uuid::new_v4()).unwrap();
        let mut rx = FileReceiver::new(&t.path().join("inbox"), &offer, 1 << 20).unwrap();
        rx.write_chunk(&s.next_chunk().unwrap().unwrap()).unwrap();
        let d = rx.finish().unwrap();
        assert!(!d.ok);
        assert!(d.reason.unwrap().starts_with("incomplete"));
    }

    #[test]
    fn hostile_offer_name_stays_in_inbox() {
        let t = tempfile::tempdir().unwrap();
        let inbox = t.path().join("inbox");
        let src = big_file(t.path(), "x.bin", 10);
        let (mut s, mut offer) = FileSender::open(&src, uuid::Uuid::new_v4()).unwrap();
        offer.name = "../../../.ssh/authorized_keys".into();
        let mut rx = FileReceiver::new(&inbox, &offer, 100).unwrap();
        rx.write_chunk(&s.next_chunk().unwrap().unwrap()).unwrap();
        let (d, p) = rx.finish_with_path().unwrap();
        assert!(d.ok);
        let p = p.unwrap();
        assert_eq!(p.parent().unwrap(), fs::canonicalize(&inbox).unwrap());
        assert_eq!(p.file_name().unwrap(), "authorized_keys");
    }
}
