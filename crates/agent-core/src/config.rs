//! `AgentConfig` defaults and TOML loading, plus the live-mutable [`Policy`] subset.
use crate::AgentConfig;
use agent_protocol::{Brain, SettingsUpdate};
use std::path::{Path, PathBuf};

pub const DEFAULT_SHELL_ALLOWLIST: &[&str] = &[
    "ls",
    "cat",
    "df",
    "du",
    "free",
    "uptime",
    "whoami",
    "date",
    "uname",
    "ip",
    "ping",
    "git",
    "grep",
    "find",
    "head",
    "tail",
    "wc",
    "ps",
    "nvidia-smi",
    "pactl",
    "playerctl",
    "hyprctl",
];

fn home() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from("."))
}

pub(crate) fn default_config() -> AgentConfig {
    let home = home();
    let data_dir = dirs::data_local_dir()
        .unwrap_or_else(|| home.join(".local/share"))
        .join("autopilot");
    let shared_roots = ["Documents", "Downloads", "Desktop", "Pictures"]
        .iter()
        .map(|n| (n.to_string(), home.join(n)))
        .filter(|(_, p)| p.is_dir())
        .collect();
    AgentConfig {
        data_dir,
        shared_roots,
        laya_url: "http://127.0.0.1:8765".into(),
        ollama_url: None,
        ollama_model: None,
        cloud_enabled: true,
        cloud_allow_high_sensitivity: false,
        preferred_cloud: "claude".into(),
        claude_model: None,
        openai_model: None,
        gemini_model: None,
        shell_allowlist: DEFAULT_SHELL_ALLOWLIST
            .iter()
            .map(|s| s.to_string())
            .collect(),
        approval_timeout_secs: 60,
        max_agent_steps: 12,
    }
}

impl AgentConfig {
    /// Load from a TOML file. A missing file yields the defaults; a malformed file is an error
    /// (silently falling back could e.g. re-enable cloud routing the user disabled).
    /// Missing keys take their default values.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(s) => Self::from_toml(&s),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(anyhow::anyhow!("reading {}: {e}", path.display())),
        }
    }

    pub fn from_toml(s: &str) -> anyhow::Result<Self> {
        let mut cfg: AgentConfig = toml::from_str(s)?;
        cfg.sanitize();
        Ok(cfg)
    }

    fn sanitize(&mut self) {
        self.approval_timeout_secs = self.approval_timeout_secs.clamp(5, 600);
        self.max_agent_steps = self.max_agent_steps.clamp(1, 50);
        self.preferred_cloud = self.preferred_cloud.to_ascii_lowercase();
    }
}

/// Router/approval knobs that `settings.update` can change at runtime.
#[derive(Debug, Clone, PartialEq)]
pub struct Policy {
    pub cloud_enabled: bool,
    pub cloud_allow_high_sensitivity: bool,
    pub preferred_cloud: Brain,
}

impl Policy {
    pub fn from_config(c: &AgentConfig) -> Self {
        Self {
            cloud_enabled: c.cloud_enabled,
            cloud_allow_high_sensitivity: c.cloud_allow_high_sensitivity,
            preferred_cloud: brain_from_name(&c.preferred_cloud).unwrap_or(Brain::Claude),
        }
    }

    pub fn apply(&mut self, u: &SettingsUpdate) {
        if let Some(v) = u.cloud_enabled {
            self.cloud_enabled = v;
        }
        if let Some(v) = u.cloud_allow_high_sensitivity {
            self.cloud_allow_high_sensitivity = v;
        }
        if let Some(b) = u.preferred_cloud
            && is_cloud(b)
        {
            self.preferred_cloud = b;
        }
    }
}

pub fn brain_from_name(s: &str) -> Option<Brain> {
    match s.to_ascii_lowercase().as_str() {
        "claude" | "anthropic" => Some(Brain::Claude),
        "openai" | "gpt" => Some(Brain::Openai),
        "gemini" | "google" => Some(Brain::Gemini),
        _ => None,
    }
}

pub fn is_cloud(b: Brain) -> bool {
    matches!(b, Brain::Claude | Brain::Openai | Brain::Gemini)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults() {
        let c = AgentConfig::default();
        assert!(c.data_dir.ends_with("autopilot"));
        assert_eq!(c.laya_url, "http://127.0.0.1:8765");
        assert!(c.cloud_enabled);
        assert!(!c.cloud_allow_high_sensitivity);
        assert_eq!(c.preferred_cloud, "claude");
        assert_eq!(c.approval_timeout_secs, 60);
        assert_eq!(c.max_agent_steps, 12);
        assert!(c.shell_allowlist.iter().any(|s| s == "hyprctl"));
        assert!(!c.shell_allowlist.iter().any(|s| s == "rm"));
        for (_, p) in &c.shared_roots {
            assert!(p.is_dir());
        }
    }

    #[test]
    fn toml_partial_and_missing() {
        let c = AgentConfig::from_toml(
            "cloud_enabled = false\npreferred_cloud = \"Gemini\"\nmax_agent_steps = 3\nshared_roots = [[\"Docs\", \"/tmp\"]]\n",
        )
        .unwrap();
        assert!(!c.cloud_enabled);
        assert_eq!(c.preferred_cloud, "gemini");
        assert_eq!(c.max_agent_steps, 3);
        assert_eq!(c.shared_roots[0].0, "Docs");
        assert_eq!(c.approval_timeout_secs, 60);
        assert!(AgentConfig::from_toml("cloud_enabled = \"yes\"").is_err());
        let missing = AgentConfig::load(Path::new("/nonexistent/autopilot.toml")).unwrap();
        assert!(missing.cloud_enabled);
    }

    #[test]
    fn policy_apply() {
        let mut p = Policy::from_config(&AgentConfig::default());
        p.apply(&SettingsUpdate {
            cloud_enabled: Some(false),
            preferred_cloud: Some(Brain::Rules),
            ..Default::default()
        });
        assert!(!p.cloud_enabled);
        assert_eq!(p.preferred_cloud, Brain::Claude);
        p.apply(&SettingsUpdate {
            preferred_cloud: Some(Brain::Openai),
            ..Default::default()
        });
        assert_eq!(p.preferred_cloud, Brain::Openai);
    }
}
