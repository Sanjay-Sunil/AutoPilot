//! Router policy (spec §8). The decider (Laya or keyword heuristics) proposes; this deterministic
//! code has the final say on where a message is processed.
use crate::config::{Policy, is_cloud};
use agent_llm::LayaDecision;
use agent_protocol::{Brain, CloudReason, RiskTier, Sensitivity};

/// Confidence below which a cloud brain is preferred (when allowed).
pub const LOW_CONFIDENCE: f32 = 0.55;
/// `needs_cloud` probability at/above which a cloud brain is preferred.
pub const NEEDS_CLOUD: f32 = 0.5;

/// What is currently available to route to.
#[derive(Debug, Clone, Default)]
pub struct Availability {
    /// Cloud brains with an API key, any order.
    pub cloud: Vec<Brain>,
    /// A local LLM (Ollama) is configured.
    pub local: bool,
    pub online: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RouteChoice {
    Cloud(Brain, CloudReason),
    Local,
    /// Nothing may/can handle it; the string is an honest explanation for the user.
    Unavailable(String),
}

/// Cloud fallback order after the preferred provider.
pub const CLOUD_ORDER: [Brain; 3] = [Brain::Claude, Brain::Openai, Brain::Gemini];

pub fn cloud_order(preferred: Brain) -> Vec<Brain> {
    let mut v = Vec::with_capacity(3);
    if is_cloud(preferred) {
        v.push(preferred);
    }
    for b in CLOUD_ORDER {
        if !v.contains(&b) {
            v.push(b);
        }
    }
    v
}

pub fn pick_cloud(policy: &Policy, avail: &Availability) -> Option<Brain> {
    cloud_order(policy.preferred_cloud)
        .into_iter()
        .find(|b| avail.cloud.contains(b))
}

/// Whether content of `sensitivity` may be sent to a cloud brain at all.
pub fn cloud_allowed(policy: &Policy, sensitivity: Sensitivity) -> bool {
    policy.cloud_enabled
        && (sensitivity != Sensitivity::High || policy.cloud_allow_high_sensitivity)
}

pub fn route(
    d: &LayaDecision,
    needs_vision: bool,
    policy: &Policy,
    avail: &Availability,
) -> RouteChoice {
    let permitted = cloud_allowed(policy, d.sensitivity) && avail.online;
    let cloud = if permitted {
        pick_cloud(policy, avail)
    } else {
        None
    };

    let reason = if needs_vision {
        Some(CloudReason::Vision)
    } else if d.intent == "multi_step_task" {
        Some(CloudReason::ComplexReasoning)
    } else if d.needs_cloud >= NEEDS_CLOUD {
        Some(if d.intent == "question" {
            CloudReason::LongGeneration
        } else {
            CloudReason::ComplexReasoning
        })
    } else if d.intent == "question" {
        Some(CloudReason::LongGeneration)
    } else if d.intent_confidence < LOW_CONFIDENCE {
        Some(CloudReason::LowConfidence)
    } else {
        None
    };

    match (reason, cloud) {
        (Some(r), Some(b)) => RouteChoice::Cloud(b, r),
        _ if avail.local => RouteChoice::Local,
        // No local LLM: the cloud is the only brain left; use it when policy permits.
        (r, Some(b)) => RouteChoice::Cloud(b, r.unwrap_or(CloudReason::ComplexReasoning)),
        _ => RouteChoice::Unavailable(unavailable_reason(d.sensitivity, policy, avail)),
    }
}

fn unavailable_reason(s: Sensitivity, policy: &Policy, avail: &Availability) -> String {
    let tail = "and no local model (Ollama) is configured.";
    if s == Sensitivity::High && !policy.cloud_allow_high_sensitivity {
        format!(
            "This looks sensitive, so I won't send it to a cloud model (you can allow that in settings), {tail}"
        )
    } else if !policy.cloud_enabled {
        format!("Cloud models are turned off in settings, {tail}")
    } else if !avail.online {
        format!("I'm offline right now, {tail}")
    } else {
        format!(
            "I need a cloud model for this but no API key is set (Claude, OpenAI or Gemini), {tail}"
        )
    }
}

const HIGH_SENS: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "secret",
    "api key",
    "apikey",
    "api_key",
    "token",
    "private key",
    "ssh key",
    "credit card",
    "card number",
    "cvv",
    "iban",
    "bank",
    "ssn",
    "social security",
    "2fa",
    "otp",
    "one-time code",
    "seed phrase",
    "recovery phrase",
    "mnemonic",
    "wallet",
    "clipboard",
    "keyring",
    ".env",
    "id_rsa",
    "id_ed25519",
    "medical",
    "diagnosis",
    "salary",
];
const MED_SENS: &[&str] = &[
    "email",
    "message",
    "chat",
    "whatsapp",
    "telegram",
    "signal",
    "photo",
    "document",
    "contract",
    "invoice",
    "address",
    "phone number",
];
const DESTRUCTIVE: &[&str] = &[
    "delete",
    "remove",
    "erase",
    "wipe",
    "kill",
    "rm ",
    "format",
    "shutdown",
    "shut down",
    "reboot",
    "restart",
    "suspend",
    "uninstall",
    "overwrite",
    "drop ",
    "purge",
    "pay ",
    "buy ",
    "purchase",
    "send money",
    "transfer money",
];
const WRITE: &[&str] = &[
    "write", "create", "save", "send", "type", "move", "rename", "install", "edit", "change",
    "set ", "update", "click", "fill", "submit", "post", "reply", "copy", "lock", "close", "press",
    "make",
];
const CLOUDY: &[&str] = &[
    "summar",
    "explain",
    "write ",
    "draft",
    "compose",
    "plan",
    "compare",
    "why",
    "how do",
    "how to",
    "how can",
    "analy",
    "translate",
    "rewrite",
    "research",
    "describe",
    "review",
    "poem",
    "story",
    "essay",
    "code",
    "debug",
    "fix ",
    "figure out",
    "find out",
    "what does",
    "what's on",
    "look at",
    "read the",
    "tell me about",
];

fn has_any(low: &str, words: &[&str]) -> bool {
    words.iter().any(|w| low.contains(w))
}

pub fn keyword_sensitivity(low: &str) -> Sensitivity {
    if has_any(low, HIGH_SENS) {
        Sensitivity::High
    } else if has_any(low, MED_SENS) {
        Sensitivity::Medium
    } else {
        Sensitivity::Low
    }
}

pub fn keyword_risk(low: &str) -> RiskTier {
    if has_any(low, DESTRUCTIVE) {
        RiskTier::Destructive
    } else if has_any(low, WRITE) {
        RiskTier::Write
    } else {
        RiskTier::Read
    }
}

/// Keyword fallback when Laya is down. Conservative: unknown => cloud-leaning, risk upgraded.
pub fn heuristic_decision(text: &str) -> LayaDecision {
    let low = text.to_lowercase();
    let words = low.split_whitespace().count();
    let multi = low.contains(" and ") || low.contains(" then ") || words > 14;
    let intent = if multi {
        "multi_step_task"
    } else if has_any(&low, &["screen", "screenshot", "what's on my"]) {
        "screen"
    } else if has_any(
        &low,
        &[
            "browser",
            "website",
            "http",
            ".com",
            "google ",
            "search the web",
        ],
    ) {
        "browser"
    } else if has_any(&low, &["clipboard"]) {
        "clipboard"
    } else if has_any(
        &low,
        &[
            "file",
            "folder",
            "documents",
            "downloads",
            "desktop",
            "pictures",
        ],
    ) {
        "files"
    } else if has_any(&low, &["window", "workspace"]) {
        "window_control"
    } else if has_any(&low, &["volume", "brightness", "mute", "media", "lock"]) {
        "system_control"
    } else if has_any(
        &low,
        &[
            "cpu", "memory", "ram", "battery", "disk", "process", "running",
        ],
    ) {
        "system_info"
    } else if has_any(&low, &["run ", "command", "terminal", "shell"]) {
        "shell"
    } else if low.starts_with("open ") || low.starts_with("launch ") {
        "open_app"
    } else if low.starts_with("type ") || low.starts_with("press ") {
        "type_or_keys"
    } else {
        "question"
    };
    let needs_cloud = if multi || has_any(&low, CLOUDY) {
        0.8
    } else {
        0.3
    };
    LayaDecision {
        intent: intent.into(),
        intent_confidence: 0.5,
        risk: keyword_risk(&low),
        sensitivity: keyword_sensitivity(&low),
        needs_cloud,
        latency_ms: 0,
    }
}

/// Deterministic floor over a model decision: never let the model *lower* sensitivity or risk
/// below what the keyword scan sees, and treat text that redaction changes as at least medium.
pub fn harden(mut d: LayaDecision, text: &str, redacted_changed: bool) -> LayaDecision {
    let low = text.to_lowercase();
    d.sensitivity = d.sensitivity.max(keyword_sensitivity(&low));
    if redacted_changed {
        d.sensitivity = d.sensitivity.max(Sensitivity::Medium);
    }
    d.risk = d.risk.max(keyword_risk(&low));
    if !agent_llm::INTENTS.contains(&d.intent.as_str()) {
        d.intent = "question".into();
        d.intent_confidence = d.intent_confidence.min(0.4);
    }
    d.intent_confidence = d.intent_confidence.clamp(0.0, 1.0);
    d.needs_cloud = d.needs_cloud.clamp(0.0, 1.0);
    d
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn policy(enabled: bool, high: bool) -> Policy {
        Policy {
            cloud_enabled: enabled,
            cloud_allow_high_sensitivity: high,
            preferred_cloud: Brain::Claude,
        }
    }

    fn dec(intent: &str, conf: f32, s: Sensitivity, nc: f32) -> LayaDecision {
        LayaDecision {
            intent: intent.into(),
            intent_confidence: conf,
            risk: RiskTier::Read,
            sensitivity: s,
            needs_cloud: nc,
            latency_ms: 1,
        }
    }

    fn all_cloud() -> Availability {
        Availability {
            cloud: vec![Brain::Gemini, Brain::Openai, Brain::Claude],
            local: true,
            online: true,
        }
    }

    #[test]
    fn routes() {
        let p = policy(true, false);
        let a = all_cloud();
        assert_eq!(
            route(
                &dec("multi_step_task", 0.9, Sensitivity::Low, 0.9),
                false,
                &p,
                &a
            ),
            RouteChoice::Cloud(Brain::Claude, CloudReason::ComplexReasoning)
        );
        assert_eq!(
            route(&dec("open_app", 0.9, Sensitivity::Low, 0.1), false, &p, &a),
            RouteChoice::Local
        );
        assert_eq!(
            route(&dec("open_app", 0.2, Sensitivity::Low, 0.1), false, &p, &a),
            RouteChoice::Cloud(Brain::Claude, CloudReason::LowConfidence)
        );
        assert_eq!(
            route(&dec("screen", 0.9, Sensitivity::Low, 0.1), true, &p, &a),
            RouteChoice::Cloud(Brain::Claude, CloudReason::Vision)
        );
        // High sensitivity stays local.
        assert_eq!(
            route(
                &dec("multi_step_task", 0.9, Sensitivity::High, 0.9),
                false,
                &p,
                &a
            ),
            RouteChoice::Local
        );
        // ... and is refused honestly when there is no local model.
        let no_local = Availability {
            local: false,
            ..all_cloud()
        };
        assert!(matches!(
            route(&dec("question", 0.9, Sensitivity::High, 0.9), false, &p, &no_local),
            RouteChoice::Unavailable(r) if r.contains("sensitive")
        ));
        // Allowed explicitly.
        assert!(matches!(
            route(
                &dec("question", 0.9, Sensitivity::High, 0.9),
                false,
                &policy(true, true),
                &no_local
            ),
            RouteChoice::Cloud(Brain::Claude, _)
        ));
        // No local model and simple intent: cloud as the only brain.
        assert!(matches!(
            route(
                &dec("open_app", 0.9, Sensitivity::Low, 0.0),
                false,
                &p,
                &no_local
            ),
            RouteChoice::Cloud(_, _)
        ));
        // Cloud disabled / offline / no key.
        let none = Availability {
            cloud: vec![],
            local: false,
            online: true,
        };
        assert!(
            matches!(route(&dec("question", 0.9, Sensitivity::Low, 0.9), false, &p, &none),
            RouteChoice::Unavailable(r) if r.contains("API key"))
        );
        assert!(
            matches!(route(&dec("question", 0.9, Sensitivity::Low, 0.9), false, &policy(false, false), &no_local),
            RouteChoice::Unavailable(r) if r.contains("turned off"))
        );
        let offline = Availability {
            online: false,
            ..no_local.clone()
        };
        assert!(
            matches!(route(&dec("question", 0.9, Sensitivity::Low, 0.9), false, &p, &offline),
            RouteChoice::Unavailable(r) if r.contains("offline"))
        );
    }

    #[test]
    fn provider_order() {
        let mut p = policy(true, false);
        let a = Availability {
            cloud: vec![Brain::Gemini, Brain::Openai],
            local: false,
            online: true,
        };
        assert_eq!(pick_cloud(&p, &a), Some(Brain::Openai));
        p.preferred_cloud = Brain::Gemini;
        assert_eq!(pick_cloud(&p, &a), Some(Brain::Gemini));
        assert_eq!(
            cloud_order(Brain::Openai),
            vec![Brain::Openai, Brain::Claude, Brain::Gemini]
        );
        assert_eq!(cloud_order(Brain::Rules), CLOUD_ORDER.to_vec());
    }

    #[test]
    fn heuristics() {
        let d = heuristic_decision("what's my bank password");
        assert_eq!(d.sensitivity, Sensitivity::High);
        let d = heuristic_decision("delete the old logs");
        assert_eq!(d.risk, RiskTier::Destructive);
        let d = heuristic_decision("open firefox and search for rust docs");
        assert_eq!(d.intent, "multi_step_task");
        assert!(d.needs_cloud >= NEEDS_CLOUD);
        let d = heuristic_decision("explain quantum computing");
        assert_eq!(d.intent, "question");
        let d = harden(
            dec("bogus", 0.9, Sensitivity::Low, 2.0),
            "paste my api key",
            false,
        );
        assert_eq!(d.sensitivity, Sensitivity::High);
        assert_eq!(d.intent, "question");
        assert!(d.needs_cloud <= 1.0);
        let d = harden(dec("files", 0.9, Sensitivity::Low, 0.0), "x", true);
        assert_eq!(d.sensitivity, Sensitivity::Medium);
    }

    fn sens() -> impl Strategy<Value = Sensitivity> {
        prop_oneof![
            Just(Sensitivity::Low),
            Just(Sensitivity::Medium),
            Just(Sensitivity::High)
        ]
    }

    proptest! {
        #[test]
        fn high_sensitivity_never_cloud_unless_allowed(
            intent in proptest::sample::select(agent_llm::INTENTS.to_vec()),
            conf in 0.0f32..=1.0, nc in 0.0f32..=1.0, vision: bool,
            enabled: bool, allow_high: bool, local: bool, online: bool,
            cloud_mask in 0u8..8, s in sens(), text in ".{0,40}",
        ) {
            let cloud: Vec<Brain> = CLOUD_ORDER.iter().enumerate()
                .filter(|(i, _)| cloud_mask & (1 << i) != 0).map(|(_, b)| *b).collect();
            let a = Availability { cloud: cloud.clone(), local, online };
            let p = Policy { cloud_enabled: enabled, cloud_allow_high_sensitivity: allow_high, preferred_cloud: Brain::Claude };
            let d = harden(dec(intent, conf, s, nc), &text, false);
            let r = route(&d, vision, &p, &a);
            if let RouteChoice::Cloud(b, _) = r {
                prop_assert!(enabled && online);
                prop_assert!(cloud.contains(&b));
                prop_assert!(d.sensitivity != Sensitivity::High || allow_high);
            }
            if d.sensitivity == Sensitivity::High && !allow_high {
                prop_assert!(!matches!(r, RouteChoice::Cloud(..)));
            }
            if local { prop_assert!(!matches!(r, RouteChoice::Unavailable(_))); }
        }

        #[test]
        fn harden_never_lowers(s in sens(), text in ".{0,60}", changed: bool) {
            let d = harden(dec("files", 0.9, s, 0.0), &text, changed);
            prop_assert!(d.sensitivity >= s);
            prop_assert!(d.sensitivity >= keyword_sensitivity(&text.to_lowercase()));
        }
    }
}
