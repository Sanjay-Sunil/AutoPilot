//! File transfer state machine on top of agent-files (chunking, hashing, path safety live there).
//! Laptop -> phone: `file.request` -> `file.offer` -> (optional `file.accept{offset}`) -> chunks -> `file.done`.
//! Phone -> laptop: `file.offer` -> approval if big/executable -> `file.accept{offset}` -> chunks -> `file.done`.
use agent_files::{FileReceiver, FileSender};
use agent_protocol::{FileDone, FileOffer, Message};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub const APPROVAL_SIZE: u64 = 50 * 1024 * 1024;
pub const MAX_INCOMING: u64 = 8 * 1024 * 1024 * 1024;
/// How long to wait for a `file.accept` before streaming from offset 0 anyway.
pub const ACCEPT_WAIT: Duration = Duration::from_secs(2);
const MAX_OUTGOING_KEPT: usize = 64;

const EXEC_EXT: &[&str] = &[
    "exe", "msi", "bat", "cmd", "com", "scr", "ps1", "vbs", "js", "jar", "sh", "bash", "zsh",
    "fish", "py", "pl", "rb", "php", "appimage", "deb", "rpm", "run", "bin", "elf", "so", "dll",
    "desktop", "apk", "dmg", "pkg", "lnk", "service", "msix", "reg",
];

pub fn is_executable_name(name: &str) -> bool {
    let low = name.to_ascii_lowercase();
    match low.rsplit_once('.') {
        Some((_, ext)) => EXEC_EXT.contains(&ext),
        None => false,
    }
}

pub fn incoming_needs_approval(o: &FileOffer) -> bool {
    o.size > APPROVAL_SIZE || is_executable_name(&o.name)
}

pub fn safe_incoming_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && !name.contains(['/', '\\', '\0'])
        && name != "."
        && name != ".."
        && !name.starts_with('.')
}

pub struct Outgoing {
    pub path: PathBuf,
    pub offer: FileOffer,
    pub accept: Option<oneshot::Sender<u64>>,
    pub cancel: CancellationToken,
}

#[derive(Default)]
pub struct Transfers {
    pub incoming: Mutex<HashMap<Uuid, FileReceiver>>,
    pub outgoing: Mutex<HashMap<Uuid, Outgoing>>,
}

impl Transfers {
    pub fn insert_outgoing(&self, id: Uuid, o: Outgoing) {
        let mut g = self.outgoing.lock().unwrap();
        if g.len() >= MAX_OUTGOING_KEPT {
            let finished: Vec<Uuid> = g
                .iter()
                .filter(|(_, v)| v.accept.is_none())
                .map(|(k, _)| *k)
                .take(g.len() + 1 - MAX_OUTGOING_KEPT)
                .collect();
            for k in finished {
                g.remove(&k);
            }
        }
        g.insert(id, o);
    }

    pub fn cancel_all(&self) {
        for (_, o) in self.outgoing.lock().unwrap().drain() {
            o.cancel.cancel();
        }
        // Dropping receivers keeps their `.part` files, so a later offer can resume.
        self.incoming.lock().unwrap().clear();
    }
}

/// Blocking: stream `path` from `offset` as `file.chunk`s, then `file.done`.
pub fn stream_file_blocking(
    path: PathBuf,
    offer: FileOffer,
    offset: u64,
    out: mpsc::Sender<Message>,
    cancel: CancellationToken,
) -> anyhow::Result<u64> {
    let (mut sender, _) = FileSender::open(&path, offer.transfer_id)?;
    if offset > 0 {
        sender.seek(offset.min(offer.size))?;
    }
    let mut sent = 0u64;
    while let Some(c) = sender.next_chunk()? {
        if cancel.is_cancelled() {
            let _ = out.blocking_send(Message::FileDone(FileDone {
                transfer_id: offer.transfer_id,
                ok: false,
                sha256: offer.sha256.clone(),
                reason: Some("cancelled".into()),
            }));
            anyhow::bail!("cancelled");
        }
        sent += 1;
        out.blocking_send(Message::FileChunk(c))
            .map_err(|_| anyhow::anyhow!("session closed"))?;
    }
    out.blocking_send(Message::FileDone(FileDone {
        transfer_id: offer.transfer_id,
        ok: true,
        sha256: offer.sha256,
        reason: None,
    }))
    .map_err(|_| anyhow::anyhow!("session closed"))?;
    Ok(sent)
}

pub fn fail(id: Uuid, reason: impl Into<String>) -> Message {
    Message::FileDone(FileDone {
        transfer_id: id,
        ok: false,
        sha256: String::new(),
        reason: Some(reason.into()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer(name: &str, size: u64) -> FileOffer {
        FileOffer {
            transfer_id: Uuid::nil(),
            name: name.into(),
            size,
            sha256: String::new(),
        }
    }

    #[test]
    fn approval_rules() {
        assert!(!incoming_needs_approval(&offer("photo.jpg", 1000)));
        assert!(incoming_needs_approval(&offer(
            "photo.jpg",
            APPROVAL_SIZE + 1
        )));
        assert!(incoming_needs_approval(&offer("setup.EXE", 10)));
        assert!(incoming_needs_approval(&offer("x.AppImage", 10)));
        assert!(incoming_needs_approval(&offer("run.sh", 10)));
        assert!(!incoming_needs_approval(&offer("notes", 10)));
    }

    #[test]
    fn names() {
        assert!(safe_incoming_name("a.txt"));
        for bad in ["", "../a", "a/b", "a\\b", ".bashrc", "..", "x\0"] {
            assert!(!safe_incoming_name(bad), "{bad:?}");
        }
    }
}
