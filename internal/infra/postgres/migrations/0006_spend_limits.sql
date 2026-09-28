-- +goose Up
-- An account's own spend limits. NULL: it inherits the global defaults (settings
-- key spend_limits). '[]': no limits. Otherwise its own set, which replaces the
-- defaults entirely. JSON: [{"window_minutes": 120, "amount_usd": 10}].
ALTER TABLE users ADD COLUMN spend_limits jsonb;

-- One row per spend-limit window an account has opened: live while
-- now < started_at + window_minutes, expired (and reopened by the next admitted
-- request) after. The usage ledger adds every recorded request's cost to all of
-- its owner's rows in the transaction that writes the request.
CREATE TABLE limit_windows (
    user_id        uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    window_minutes integer NOT NULL CHECK (window_minutes BETWEEN 1 AND 525600),
    started_at     timestamptz NOT NULL,
    spent_usd      double precision NOT NULL DEFAULT 0
        CHECK (spent_usd >= 0 AND spent_usd <> 'NaN' AND spent_usd <> 'Infinity'),
    PRIMARY KEY (user_id, window_minutes)
);

-- +goose Down
DROP TABLE limit_windows;
ALTER TABLE users DROP COLUMN spend_limits;
