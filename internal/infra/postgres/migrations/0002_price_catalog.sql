-- +goose Up

-- The price catalog's prices, replaced whole by every catalog check that finds a
-- change. model_prices stays the administrator's manual overrides, which win over
-- these. Same rules as model_prices.
CREATE TABLE catalog_prices (
    provider    text NOT NULL CHECK (provider <> ''),
    model       text NOT NULL CHECK (model <> ''),
    input       double precision NOT NULL CHECK (input >= 0 AND input <> 'NaN' AND input <> 'Infinity'),
    output      double precision NOT NULL CHECK (output >= 0 AND output <> 'NaN' AND output <> 'Infinity'),
    cache_read  double precision NOT NULL CHECK (cache_read >= 0 AND cache_read <> 'NaN' AND cache_read <> 'Infinity'),
    cache_write double precision NOT NULL CHECK (cache_write >= 0 AND cache_write <> 'NaN' AND cache_write <> 'Infinity'),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, model)
);

-- The state of the catalog's checks: one row, created here. etag and last_modified
-- are the validators of the last catalog accepted, fingerprint the source (URL and
-- parser version) they were stored under; checked_at the last successful
-- check; changed_at the last change of catalog_prices; last_error why the last
-- check failed, NULL once one succeeds.
CREATE TABLE catalog_state (
    id            boolean PRIMARY KEY DEFAULT true CHECK (id),
    etag          text NOT NULL DEFAULT '',
    last_modified text NOT NULL DEFAULT '',
    fingerprint   text NOT NULL DEFAULT '',
    checked_at    timestamptz,
    changed_at    timestamptz,
    last_error    text
);
INSERT INTO catalog_state DEFAULT VALUES;

-- +goose Down
DROP TABLE catalog_state, catalog_prices;
