-- +goose Up
CREATE TABLE users (
    id                   uuid PRIMARY KEY,
    kind                 text NOT NULL CHECK (kind IN ('human', 'service')),
    email                text,
    display_name         text NOT NULL DEFAULT '',
    role                 text NOT NULL CHECK (role IN ('user', 'admin')),
    status               text NOT NULL CHECK (status IN ('active', 'blocked')),
    policy               jsonb NOT NULL DEFAULT '[]'::jsonb,
    policy_managed_by    text NOT NULL CHECK (policy_managed_by IN ('local', 'idp')),
    must_change_password boolean NOT NULL DEFAULT false,
    last_seen_at         timestamptz,
    created_at           timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE user_passwords (
    user_id    uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    hash       text NOT NULL,
    expires_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE user_identities (
    user_id   uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    issuer    text NOT NULL,
    subject   text NOT NULL,
    linked_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (issuer, subject)
);

CREATE TABLE pending_identities (
    user_id        uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    issuer         text NOT NULL,
    expected_email text NOT NULL,
    expires_at     timestamptz NOT NULL
);

-- A session row carries identity and a window, and nothing else. Whether a session is
-- restricted is NOT stored here: it is users.must_change_password, read at every
-- request. A boolean copied into this table would be a second source for one fact, and
-- the copy would be wrong for every session that was already open when an
-- administrator issued a temporary password.
CREATE TABLE sessions (
    id         text PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ip         text NOT NULL DEFAULT '',
    user_agent text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);

CREATE TABLE api_tokens (
    id           uuid PRIMARY KEY,
    user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label        text NOT NULL,
    hash         text NOT NULL UNIQUE,
    prefix       text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    revoked_at   timestamptz,
    revoked_by   uuid REFERENCES users(id)
);

CREATE TABLE usage_events (
    id                  bigserial PRIMARY KEY,
    at                  timestamptz NOT NULL,
    user_id             uuid REFERENCES users(id) ON DELETE SET NULL,
    token_id            uuid REFERENCES api_tokens(id) ON DELETE SET NULL,
    provider            text NOT NULL,
    model               text NOT NULL,
    alias               text NOT NULL DEFAULT '',
    stream              boolean NOT NULL DEFAULT false,
    service_tier        text NOT NULL DEFAULT '',
    tokens_input        bigint NOT NULL DEFAULT 0,
    tokens_output       bigint NOT NULL DEFAULT 0,
    tokens_reasoning    bigint NOT NULL DEFAULT 0,
    tokens_cache_read   bigint NOT NULL DEFAULT 0,
    tokens_cache_write  bigint NOT NULL DEFAULT 0,
    tokens_total        bigint NOT NULL DEFAULT 0,
    breakdown_quality   text NOT NULL DEFAULT '',
    latency_ms          integer NOT NULL DEFAULT 0,
    ttft_ms             integer NOT NULL DEFAULT 0,
    status_code         integer NOT NULL DEFAULT 0,
    failed              boolean NOT NULL DEFAULT false,
    vendor_account_id   text NOT NULL DEFAULT ''
);

-- Uniqueness must be case-insensitive because ByEmail is: a plain UNIQUE would let
-- A@example.com and a@example.com both exist, and the lookup would then silently
-- return an arbitrary one of two rows with possibly different role, status and policy.
-- Sign-in and the bootstrap-admin idempotence check both read through it, so an
-- ambiguous answer there is an authentication-correctness problem. Enforcing it in the
-- schema binds every writer; lower-casing on write would bind only this repository and
-- would destroy the display capitalisation the cabinet renders.
CREATE UNIQUE INDEX users_email_lower_key ON users (lower(email));

-- The same defect, the same fix: PendingByEmail folds case, so two invitations for one
-- issuer whose addresses differ only in case would make the lookup return an arbitrary
-- one of them, and the person at that mailbox would be linked to whichever account
-- the planner happened to read first.
CREATE UNIQUE INDEX pending_identities_issuer_email_lower_key
    ON pending_identities (issuer, lower(expected_email));

CREATE INDEX usage_events_user_at_idx ON usage_events (user_id, at DESC);
CREATE INDEX usage_events_at_idx ON usage_events (at DESC);

CREATE TABLE audit_events (
    id            bigserial PRIMARY KEY,
    at            timestamptz NOT NULL DEFAULT now(),
    actor_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    action        text NOT NULL,
    target        text NOT NULL DEFAULT '',
    detail        jsonb NOT NULL DEFAULT '{}'::jsonb,
    ip            text NOT NULL DEFAULT '',
    user_agent    text NOT NULL DEFAULT ''
);

CREATE INDEX audit_events_actor_at_idx ON audit_events (actor_user_id, at DESC);
-- An account's activity page reads the events it performed, the events whose target
-- it is, and the events about its tokens (which name it as owner_id). Every branch of
-- that OR needs its own index, or the planner cannot combine them and scans the whole
-- log — which is never pruned.
CREATE INDEX audit_events_target_at_idx ON audit_events (target, at DESC);
CREATE INDEX audit_events_owner_at_idx ON audit_events ((detail->>'owner_id'), at DESC)
    WHERE detail->>'owner_id' IS NOT NULL;

CREATE TABLE login_attempts (
    email           text PRIMARY KEY,
    failures        integer NOT NULL DEFAULT 0,
    locked_until    timestamptz,
    -- The last charged attempt. A count whose last attempt is older than the lock
    -- window is stale and starts over, so the limit is per window, not per lifetime.
    last_failure_at timestamptz
);

CREATE TABLE settings (
    key        text PRIMARY KEY,
    value      jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by uuid REFERENCES users(id)
);

-- The price list the metrics cost estimate reads, in US dollars per million tokens.
-- An estimate of work done, not a bill: the vendor's invoice is the bill. Every rate
-- is non-negative and one (provider, model) has one price, enforced here so a writer
-- that skipped the service's validation still cannot store an ambiguous or negative
-- row. NaN is refused too: Postgres orders it above every number, so >= 0 admits it.
CREATE TABLE model_prices (
    provider    text NOT NULL CHECK (provider <> ''),
    model       text NOT NULL CHECK (model <> ''),
    input       double precision NOT NULL CHECK (input >= 0 AND input <> 'NaN' AND input <> 'Infinity'),
    output      double precision NOT NULL CHECK (output >= 0 AND output <> 'NaN' AND output <> 'Infinity'),
    cache_read  double precision NOT NULL CHECK (cache_read >= 0 AND cache_read <> 'NaN' AND cache_read <> 'Infinity'),
    cache_write double precision NOT NULL CHECK (cache_write >= 0 AND cache_write <> 'NaN' AND cache_write <> 'Infinity'),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, model)
);

-- +goose Down
DROP TABLE model_prices, settings, login_attempts, audit_events, usage_events, api_tokens,
           sessions, pending_identities, user_identities, user_passwords, users;
