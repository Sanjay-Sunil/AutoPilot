-- AutoPilot device registry (spec section 11). Metadata only: the backend never stores message
-- content, files, screen frames, or provider API keys.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE users (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    handle      TEXT NOT NULL UNIQUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- WebAuthn passkeys (webauthn-rs serialized Passkey), one user may have several.
CREATE TABLE passkeys (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id  BYTEA NOT NULL UNIQUE,
    passkey        JSONB NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at   TIMESTAMPTZ
);
CREATE INDEX passkeys_user_idx ON passkeys(user_id);

CREATE TABLE devices (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL CHECK (kind IN ('laptop', 'phone')),
    -- Noise static public key (X25519, 32 bytes).
    public_key  BYTEA NOT NULL UNIQUE CHECK (octet_length(public_key) = 32),
    name        TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ,
    revoked_at  TIMESTAMPTZ
);
CREATE INDEX devices_user_idx ON devices(user_id) WHERE revoked_at IS NULL;

-- One-time pairing tokens; only the SHA-256 of the token is stored.
CREATE TABLE pairings (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    laptop_id     UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    token_hash    BYTEA NOT NULL UNIQUE,
    expires_at    TIMESTAMPTZ NOT NULL,
    claimed_by    UUID REFERENCES devices(id) ON DELETE SET NULL,
    claimed_at    TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX pairings_expiry_idx ON pairings(expires_at) WHERE claimed_at IS NULL;

-- Session metadata only (who, when, which path). No content.
CREATE TABLE sessions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    laptop_id   UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    phone_id    UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    transport   TEXT NOT NULL CHECK (transport IN ('direct', 'relay', 'webrtc')),
    started_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at    TIMESTAMPTZ,
    bytes_relayed BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX sessions_laptop_idx ON sessions(laptop_id, started_at DESC);

CREATE TABLE push_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id   UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    platform    TEXT NOT NULL CHECK (platform IN ('fcm', 'apns', 'expo')),
    token       TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (device_id, platform)
);
