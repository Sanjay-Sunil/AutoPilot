//! Short conversation memory so follow-ups work ("the code is 123456", "now open the second one").
//! Keeps the last few user/reply pairs per actor for a limited time. Exchanges that touched
//! high-sensitivity data are flagged and withheld from cloud models unless policy allows it.
use crate::tools::truncate;
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const MAX_TURNS: usize = 6;
pub const TTL: Duration = Duration::from_secs(30 * 60);
const MAX_CHARS: usize = 1500;

struct Turn {
    actor: String,
    user: String,
    reply: String,
    high: bool,
    at: Instant,
}

#[derive(Default)]
pub struct Memory {
    turns: Mutex<VecDeque<Turn>>,
}

impl Memory {
    pub fn push(&self, actor: &str, user: &str, reply: &str, high: bool) {
        self.push_at(actor, user, reply, high, Instant::now());
    }

    fn push_at(&self, actor: &str, user: &str, reply: &str, high: bool, at: Instant) {
        let mut g = self.turns.lock().unwrap();
        g.push_back(Turn {
            actor: actor.to_string(),
            user: truncate(user, MAX_CHARS),
            reply: truncate(reply, MAX_CHARS),
            high,
            at,
        });
        // Bound total size across actors too.
        while g.len() > MAX_TURNS * 4 {
            g.pop_front();
        }
    }

    /// Recent (user, reply) pairs for `actor`, oldest first. When `include_high` is false, the
    /// history is cut after the newest high-sensitivity turn is dropped, so no pair refers to
    /// content the model cannot see.
    pub fn recent(&self, actor: &str, include_high: bool) -> Vec<(String, String)> {
        self.recent_at(actor, include_high, Instant::now())
    }

    fn recent_at(&self, actor: &str, include_high: bool, now: Instant) -> Vec<(String, String)> {
        let mut g = self.turns.lock().unwrap();
        g.retain(|t| now.duration_since(t.at) < TTL);
        let mine: Vec<&Turn> = g.iter().filter(|t| t.actor == actor).collect();
        let start = if include_high {
            0
        } else {
            mine.iter().rposition(|t| t.high).map_or(0, |i| i + 1)
        };
        let from = mine.len().saturating_sub(MAX_TURNS).max(start);
        mine[from..]
            .iter()
            .map(|t| (t.user.clone(), t.reply.clone()))
            .collect()
    }

    pub fn clear(&self) {
        self.turns.lock().unwrap().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_actor_capped_and_expiring() {
        let m = Memory::default();
        let t0 = Instant::now();
        for i in 0..8 {
            m.push_at("phone", &format!("q{i}"), &format!("a{i}"), false, t0);
        }
        m.push_at("tray", "other", "x", false, t0);
        let r = m.recent_at("phone", true, t0);
        assert_eq!(r.len(), MAX_TURNS);
        assert_eq!(r[0].0, "q2");
        assert_eq!(r.last().unwrap(), &("q7".to_string(), "a7".to_string()));
        assert_eq!(m.recent_at("tray", true, t0).len(), 1);
        assert!(m.recent_at("phone", true, t0 + TTL).is_empty());
    }

    #[test]
    fn high_sensitivity_withheld() {
        let m = Memory::default();
        m.push("p", "q1", "a1", false);
        m.push("p", "show my clipboard", "hunter2", true);
        m.push("p", "q3", "a3", false);
        assert_eq!(m.recent("p", true).len(), 3);
        let r = m.recent("p", false);
        assert_eq!(r, vec![("q3".to_string(), "a3".to_string())]);
        assert!(!format!("{r:?}").contains("hunter2"));
        m.clear();
        assert!(m.recent("p", true).is_empty());
    }
}
