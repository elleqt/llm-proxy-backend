-- +goose Up
-- One row per vendor account (Claude, ChatGPT/Codex) the gateway routes through.
-- sealed is AES-256-GCM of the credential JSON upstream would have written to a
-- file; the plaintext never reaches the database.
CREATE TABLE vendor_credentials (
    id         text PRIMARY KEY,   -- upstream Auth.ID; usage_events.vendor_account_id refers to it
    provider   text NOT NULL,      -- upstream provider ("claude", "codex"), for diagnostics
    sealed     bytea NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

-- +goose Down
DELETE FROM settings WHERE key = 'vendor_credentials_import';
DROP TABLE vendor_credentials;
