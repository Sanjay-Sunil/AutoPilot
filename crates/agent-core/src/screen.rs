//! On-demand screen snapshots and a low-fps JPEG stream. Capture only while active (battery):
//! the capturer is created lazily and every capture runs on the blocking pool.
use crate::tools::Image;
use agent_capture::ScreenCapturer;
use agent_protocol::{Message, Notify, NotifyLevel, ScreenFrame, ScreenRequest, ScreenState};
use base64::Engine;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Max base64 bytes per `screen.frame` part (keeps each envelope well under the Noise limit).
pub const PART_B64: usize = 48 * 1024;

type Factory = Box<dyn Fn() -> Box<dyn ScreenCapturer> + Send + Sync>;

pub struct CaptureSource {
    factory: Factory,
    cell: OnceLock<Box<dyn ScreenCapturer>>,
}

impl CaptureSource {
    pub fn new(f: impl Fn() -> Box<dyn ScreenCapturer> + Send + Sync + 'static) -> Self {
        Self {
            factory: Box::new(f),
            cell: OnceLock::new(),
        }
    }

    /// Real backend (Hyprland/grim, X11, Windows) picked on first use.
    pub fn detect() -> Self {
        Self::new(agent_capture::detect)
    }

    pub async fn capture(self: &Arc<Self>, max_width: u32, quality: u8) -> anyhow::Result<Image> {
        let me = self.clone();
        tokio::task::spawn_blocking(move || {
            let cap = me.cell.get_or_init(|| (me.factory)());
            let f = cap.capture_jpeg(max_width, quality)?;
            Ok(Image {
                jpeg: f.jpeg,
                width: f.width,
                height: f.height,
            })
        })
        .await
        .map_err(|e| anyhow::anyhow!("capture panicked: {e}"))?
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Params {
    pub max_width: u32,
    pub quality: u8,
    pub fps: u8,
}

impl Params {
    pub fn from_request(r: &ScreenRequest) -> Self {
        Self {
            max_width: r.max_width.unwrap_or(1280).clamp(320, 3840),
            quality: r.quality.unwrap_or(60).clamp(10, 95),
            fps: r.fps.unwrap_or(2).clamp(1, 15),
        }
    }
}

pub fn frame_parts(frame_id: u64, img: &Image) -> Vec<ScreenFrame> {
    let b64 = base64::engine::general_purpose::STANDARD.encode(&img.jpeg);
    // base64 is ASCII, so byte slicing is always on a char boundary.
    let chunks: Vec<&str> = if b64.is_empty() {
        vec![""]
    } else {
        b64.as_bytes()
            .chunks(PART_B64)
            .map(|c| std::str::from_utf8(c).expect("ascii"))
            .collect()
    };
    let parts = chunks.len() as u16;
    chunks
        .into_iter()
        .enumerate()
        .map(|(i, d)| ScreenFrame {
            frame_id,
            part: i as u16,
            parts,
            width: img.width,
            height: img.height,
            data_b64: d.to_string(),
        })
        .collect()
}

type Notifier = Arc<dyn Fn(&str, &str) + Send + Sync>;

pub struct ScreenCtl {
    stream: Mutex<Option<CancellationToken>>,
    next_id: AtomicU64,
}

impl Default for ScreenCtl {
    fn default() -> Self {
        Self {
            stream: Mutex::new(None),
            next_id: AtomicU64::new(1),
        }
    }
}

impl ScreenCtl {
    pub fn is_streaming(&self) -> bool {
        self.stream
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|t| !t.is_cancelled())
    }

    /// Send one image to the phone as `screen.frame` parts. Waits for channel capacity
    /// (natural backpressure on slow links). Returns false if the channel closed.
    pub async fn send_image(&self, out: &mpsc::Sender<Message>, img: &Image) -> bool {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        for p in frame_parts(id, img) {
            if out.send(Message::ScreenFrame(p)).await.is_err() {
                return false;
            }
        }
        true
    }

    /// Stop the stream (if any). Returns true if one was running.
    pub fn stop(&self) -> bool {
        match self.stream.lock().unwrap().take() {
            Some(t) => {
                let was = !t.is_cancelled();
                t.cancel();
                was
            }
            None => false,
        }
    }

    pub fn start(
        self: &Arc<Self>,
        src: Arc<CaptureSource>,
        parent: &CancellationToken,
        p: Params,
        out: mpsc::Sender<Message>,
        notifier: Notifier,
    ) {
        let token = parent.child_token();
        if let Some(old) = self.stream.lock().unwrap().replace(token.clone()) {
            old.cancel();
        }
        let me = self.clone();
        tokio::spawn(async move {
            notifier("AutoPilot", "Screen sharing to your phone is ON");
            let _ = out
                .send(Message::ScreenState(ScreenState {
                    active: true,
                    reason: "on_demand".into(),
                }))
                .await;
            let mut tick = tokio::time::interval(Duration::from_millis(1000 / p.fps as u64));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut failures = 0u32;
            let reason = loop {
                tokio::select! {
                    _ = token.cancelled() => break "stopped",
                    _ = tick.tick() => {}
                }
                let frame = tokio::select! {
                    _ = token.cancelled() => break "stopped",
                    f = src.capture(p.max_width, p.quality) => f,
                };
                match frame {
                    Ok(img) => {
                        failures = 0;
                        if token.is_cancelled() {
                            break "stopped";
                        }
                        if !me.send_image(&out, &img).await {
                            break "disconnected";
                        }
                    }
                    Err(e) => {
                        failures += 1;
                        tracing::warn!("screen capture failed: {e}");
                        if failures >= 3 {
                            let _ = out
                                .send(Message::Notify(Notify {
                                    level: NotifyLevel::Error,
                                    text: format!("Screen capture failed: {e}"),
                                }))
                                .await;
                            break "capture_failed";
                        }
                    }
                }
            };
            token.cancel();
            let replaced = {
                let mut g = me.stream.lock().unwrap();
                let replaced = g.as_ref().is_some_and(|t| !t.is_cancelled());
                if !replaced {
                    *g = None;
                }
                replaced
            };
            if replaced {
                return;
            }
            notifier("AutoPilot", "Screen sharing stopped");
            let _ = out
                .send(Message::ScreenState(ScreenState {
                    active: false,
                    reason: reason.into(),
                }))
                .await;
        });
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use agent_capture::Frame;
    use std::sync::atomic::AtomicUsize;

    pub struct FakeCap(pub Arc<AtomicUsize>, pub usize);
    impl ScreenCapturer for FakeCap {
        fn name(&self) -> &'static str {
            "fake"
        }
        fn capture_jpeg(&self, max_width: u32, _q: u8) -> anyhow::Result<Frame> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(Frame {
                jpeg: vec![0xAB; self.1],
                width: max_width,
                height: max_width / 2,
            })
        }
    }

    #[test]
    fn splits_frames() {
        let img = Image {
            jpeg: vec![1; 100_000],
            width: 10,
            height: 5,
        };
        let parts = frame_parts(7, &img);
        assert_eq!(parts.len(), 3);
        assert!(parts.iter().all(|p| p.data_b64.len() <= PART_B64));
        assert!(parts.iter().all(|p| p.parts == 3 && p.frame_id == 7));
        let joined: String = parts.iter().map(|p| p.data_b64.as_str()).collect();
        let back = base64::engine::general_purpose::STANDARD
            .decode(joined)
            .unwrap();
        assert_eq!(back, img.jpeg);
        assert_eq!(
            frame_parts(
                1,
                &Image {
                    jpeg: vec![],
                    width: 1,
                    height: 1
                }
            )
            .len(),
            1
        );
    }

    #[test]
    fn params_clamped() {
        let p = Params::from_request(&ScreenRequest {
            action: agent_protocol::ScreenAction::Start,
            max_width: None,
            fps: Some(60),
            quality: Some(0),
        });
        assert_eq!(
            p,
            Params {
                max_width: 1280,
                quality: 10,
                fps: 15
            }
        );
    }

    #[tokio::test]
    async fn stream_start_stop() {
        let count = Arc::new(AtomicUsize::new(0));
        let c2 = count.clone();
        let src = Arc::new(CaptureSource::new(move || {
            Box::new(FakeCap(c2.clone(), 10))
        }));
        let ctl = Arc::new(ScreenCtl::default());
        let (tx, mut rx) = mpsc::channel(64);
        let root = CancellationToken::new();
        let p = Params {
            max_width: 640,
            quality: 50,
            fps: 15,
        };
        ctl.start(src, &root, p, tx, Arc::new(|_, _| {}));
        assert!(matches!(
            rx.recv().await,
            Some(Message::ScreenState(ScreenState { active: true, .. }))
        ));
        assert!(matches!(rx.recv().await, Some(Message::ScreenFrame(_))));
        assert!(ctl.is_streaming());
        assert!(ctl.stop());
        loop {
            match tokio::time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .unwrap()
            {
                Some(Message::ScreenState(s)) => {
                    assert!(!s.active);
                    break;
                }
                Some(_) => continue,
                None => panic!("closed"),
            }
        }
        let n = count.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(count.load(Ordering::SeqCst), n, "no capture after stop");
        assert!(!ctl.is_streaming());
    }
}
