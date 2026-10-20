//! API key lookup: environment first, then the OS keyring (service "autopilot").
//! Keys are never logged; errors mention only the provider name.
use anyhow::anyhow;

pub const KEYRING_SERVICE: &str = "autopilot";

/// Env vars checked (in order) for a provider.
pub fn env_vars(provider: &str) -> &'static [&'static str] {
    match provider {
        "claude" | "anthropic" => &["ANTHROPIC_API_KEY"],
        "openai" => &["OPENAI_API_KEY"],
        "gemini" | "google" => &["GEMINI_API_KEY", "GOOGLE_API_KEY"],
        _ => &[],
    }
}

/// Canonical keyring user name for a provider.
pub fn keyring_user(provider: &str) -> &str {
    match provider {
        "anthropic" => "claude",
        "google" => "gemini",
        p => p,
    }
}

/// Lookup with injectable sources (for tests). Empty / whitespace values are ignored.
pub fn lookup(
    provider: &str,
    env: impl Fn(&str) -> Option<String>,
    keyring: impl Fn(&str) -> Option<String>,
) -> Option<String> {
    let clean = |v: Option<String>| v.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty());
    env_vars(provider)
        .iter()
        .find_map(|k| clean(env(k)))
        .or_else(|| clean(keyring(keyring_user(provider))))
}

/// Read from the OS keyring; any failure (no secret service, locked, missing) => `None`.
pub fn keyring_get(user: &str) -> Option<String> {
    std::panic::catch_unwind(|| {
        keyring::Entry::new(KEYRING_SERVICE, user)
            .ok()?
            .get_password()
            .ok()
    })
    .ok()
    .flatten()
}

pub fn keyring_set(provider: &str, key: &str) -> anyhow::Result<()> {
    if key.trim().is_empty() {
        return Err(anyhow!("refusing to store an empty key for {provider}"));
    }
    let user = keyring_user(provider);
    let entry = keyring::Entry::new(KEYRING_SERVICE, user)
        .map_err(|e| anyhow!("keyring unavailable for {user}: {e}"))?;
    entry
        .set_password(key.trim())
        .map_err(|e| anyhow!("keyring write failed for {user}: {e}"))
}
