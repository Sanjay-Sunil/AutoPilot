//! Pending approvals keyed by a random uuid. Only responses matching a pending id are accepted;
//! unanswered requests expire and count as deny. The kill switch denies everything pending.
use agent_protocol::{ApprovalDecision, ApprovalRequest, Message, RiskTier};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Destructive approvals never live longer than this, whatever the config says.
pub const DESTRUCTIVE_MAX: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Approved,
    /// Write tier only: remember the tool for the rest of the task.
    ApprovedForTask,
    Denied,
    Expired,
    Cancelled,
}

impl Outcome {
    pub fn approved(self) -> bool {
        matches!(self, Self::Approved | Self::ApprovedForTask)
    }
}

struct Pending {
    tx: oneshot::Sender<ApprovalDecision>,
}

struct Cleanup<'a>(&'a Mutex<HashMap<Uuid, Pending>>, Uuid);
impl Drop for Cleanup<'_> {
    fn drop(&mut self) {
        if let Ok(mut g) = self.0.lock() {
            g.remove(&self.1);
        }
    }
}

#[derive(Default)]
pub struct Approvals {
    pending: Mutex<HashMap<Uuid, Pending>>,
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub struct Ask<'a> {
    pub task_id: Uuid,
    pub tool: &'a str,
    pub summary: &'a str,
    pub risk: RiskTier,
    pub preview: Option<String>,
}

impl Approvals {
    pub fn timeout_for(risk: RiskTier, configured: Duration) -> Duration {
        match risk {
            RiskTier::Destructive => configured.min(DESTRUCTIVE_MAX),
            _ => configured,
        }
    }

    pub fn pending_count(&self) -> usize {
        self.pending.lock().unwrap().len()
    }

    pub fn pending_ids(&self) -> Vec<Uuid> {
        self.pending.lock().unwrap().keys().copied().collect()
    }

    /// Send an `approval.request` and wait for the matching response, expiry or cancellation.
    pub async fn request(
        &self,
        out: &mpsc::Sender<Message>,
        ask: Ask<'_>,
        configured_timeout: Duration,
        cancel: &CancellationToken,
    ) -> Outcome {
        let timeout = Self::timeout_for(ask.risk, configured_timeout);
        let id = Uuid::new_v4();
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(id, Pending { tx });
        // Remove the entry however this future ends (resolved, expired, or dropped on kill).
        let _cleanup = Cleanup(&self.pending, id);
        let msg = Message::ApprovalRequest(ApprovalRequest {
            approval_id: id,
            task_id: ask.task_id,
            tool: ask.tool.to_string(),
            summary: ask.summary.to_string(),
            risk: ask.risk,
            preview: ask.preview,
            expires_at_ms: now_ms() + timeout.as_millis() as u64,
        });
        if out.send(msg).await.is_err() {
            return Outcome::Denied;
        }
        let outcome = tokio::select! {
            r = rx => match r {
                Ok(ApprovalDecision::Approve) => Outcome::Approved,
                Ok(ApprovalDecision::ApproveForTask) if ask.risk == RiskTier::Write => Outcome::ApprovedForTask,
                // "for task" is not valid for destructive actions: approve this one action only.
                Ok(ApprovalDecision::ApproveForTask) => Outcome::Approved,
                Ok(ApprovalDecision::Deny) => Outcome::Denied,
                Err(_) => Outcome::Denied,
            },
            _ = tokio::time::sleep(timeout) => Outcome::Expired,
            _ = cancel.cancelled() => Outcome::Cancelled,
        };
        outcome
    }

    /// Deliver a phone decision. False (and ignored) unless `id` is currently pending.
    pub fn respond(&self, id: Uuid, decision: ApprovalDecision) -> bool {
        match self.pending.lock().unwrap().remove(&id) {
            Some(p) => p.tx.send(decision).is_ok(),
            None => false,
        }
    }

    /// Deny every pending approval (kill switch). Returns how many were pending.
    pub fn deny_all(&self) -> usize {
        let drained: Vec<_> = self.pending.lock().unwrap().drain().collect();
        let n = drained.len();
        for (_, p) in drained {
            let _ = p.tx.send(ApprovalDecision::Deny);
        }
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn ask(risk: RiskTier) -> Ask<'static> {
        Ask {
            task_id: Uuid::nil(),
            tool: "fs.write",
            summary: "write x",
            risk,
            preview: Some("x".into()),
        }
    }

    async fn run(
        risk: RiskTier,
        timeout: Duration,
        respond: impl FnOnce(&Approvals, Uuid) + Send + 'static,
    ) -> Outcome {
        let a = Arc::new(Approvals::default());
        let (tx, mut rx) = mpsc::channel(4);
        let a2 = a.clone();
        let h = tokio::spawn(async move {
            let c = CancellationToken::new();
            a2.request(&tx, ask(risk), timeout, &c).await
        });
        let Some(Message::ApprovalRequest(req)) = rx.recv().await else {
            panic!("no request")
        };
        assert_eq!(req.risk, risk);
        assert!(req.expires_at_ms > now_ms());
        respond(&a, req.approval_id);
        let o = h.await.unwrap();
        assert_eq!(a.pending_count(), 0);
        o
    }

    #[tokio::test]
    async fn approve_deny_for_task() {
        let t = Duration::from_secs(5);
        assert_eq!(
            run(RiskTier::Write, t, |a, id| assert!(
                a.respond(id, ApprovalDecision::Approve)
            ))
            .await,
            Outcome::Approved
        );
        assert_eq!(
            run(RiskTier::Write, t, |a, id| assert!(
                a.respond(id, ApprovalDecision::Deny)
            ))
            .await,
            Outcome::Denied
        );
        assert_eq!(
            run(RiskTier::Write, t, |a, id| {
                a.respond(id, ApprovalDecision::ApproveForTask);
            })
            .await,
            Outcome::ApprovedForTask
        );
        // Destructive: "for task" degrades to a single approval.
        assert_eq!(
            run(RiskTier::Destructive, t, |a, id| {
                a.respond(id, ApprovalDecision::ApproveForTask);
            })
            .await,
            Outcome::Approved
        );
    }

    #[tokio::test]
    async fn unknown_and_replayed_ids_rejected() {
        let o = run(RiskTier::Write, Duration::from_secs(5), |a, id| {
            assert!(!a.respond(Uuid::new_v4(), ApprovalDecision::Approve));
            assert!(a.respond(id, ApprovalDecision::Deny));
            // Replay of the same id after it resolved is ignored.
            assert!(!a.respond(id, ApprovalDecision::Approve));
        })
        .await;
        assert_eq!(o, Outcome::Denied);
    }

    #[tokio::test]
    async fn expires() {
        let o = run(RiskTier::Write, Duration::from_millis(50), |_, _| {}).await;
        assert_eq!(o, Outcome::Expired);
        assert_eq!(
            Approvals::timeout_for(RiskTier::Destructive, Duration::from_secs(600)),
            DESTRUCTIVE_MAX
        );
        assert_eq!(
            Approvals::timeout_for(RiskTier::Write, Duration::from_secs(90)),
            Duration::from_secs(90)
        );
    }

    #[tokio::test]
    async fn deny_all_and_cancel() {
        let o = run(RiskTier::Destructive, Duration::from_secs(5), |a, _| {
            assert_eq!(a.deny_all(), 1);
        })
        .await;
        assert_eq!(o, Outcome::Denied);

        let a = Approvals::default();
        let (tx, mut rx) = mpsc::channel(4);
        let c = CancellationToken::new();
        let c2 = c.clone();
        tokio::spawn(async move {
            rx.recv().await;
            c2.cancel();
        });
        let o = a
            .request(&tx, ask(RiskTier::Write), Duration::from_secs(5), &c)
            .await;
        assert_eq!(o, Outcome::Cancelled);
        assert_eq!(a.pending_count(), 0);
    }
}
