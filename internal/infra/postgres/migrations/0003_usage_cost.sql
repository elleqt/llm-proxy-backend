-- +goose Up

-- Each request's estimated cost, priced when the usage sink records it, at the
-- prices in force then (app.PriceUsage), so a later price change does not rewrite
-- history. US dollars; cache_savings_usd is the net effect of prompt caching and may
-- be negative. unpriced_tokens are the tokens no rate applied to; priced says
-- whether any token was priced.
ALTER TABLE usage_events
    ADD COLUMN cost_input_usd       double precision NOT NULL DEFAULT 0
        CHECK (cost_input_usd >= 0 AND cost_input_usd <> 'NaN' AND cost_input_usd <> 'Infinity'),
    ADD COLUMN cost_output_usd      double precision NOT NULL DEFAULT 0
        CHECK (cost_output_usd >= 0 AND cost_output_usd <> 'NaN' AND cost_output_usd <> 'Infinity'),
    ADD COLUMN cost_cache_read_usd  double precision NOT NULL DEFAULT 0
        CHECK (cost_cache_read_usd >= 0 AND cost_cache_read_usd <> 'NaN' AND cost_cache_read_usd <> 'Infinity'),
    ADD COLUMN cost_cache_write_usd double precision NOT NULL DEFAULT 0
        CHECK (cost_cache_write_usd >= 0 AND cost_cache_write_usd <> 'NaN' AND cost_cache_write_usd <> 'Infinity'),
    ADD COLUMN cache_savings_usd    double precision NOT NULL DEFAULT 0
        CHECK (cache_savings_usd <> 'NaN' AND cache_savings_usd <> 'Infinity' AND cache_savings_usd <> '-Infinity'),
    ADD COLUMN unpriced_tokens      bigint NOT NULL DEFAULT 0 CHECK (unpriced_tokens >= 0),
    ADD COLUMN priced               boolean NOT NULL DEFAULT false;

-- Backfill: the rows recorded before cost was stored are priced at the price in
-- force now (a manual price, else the catalog's), with app.PriceUsage's arithmetic.
-- The kinds partition a request (reasoning is output; a negative count is zero);
-- tokens above their sum are unclassified and unpriced; a row with no classified
-- token, or whose model has no price, is not priced and all its tokens are unpriced.
WITH price AS (
    SELECT provider, model, input, output, cache_read, cache_write FROM model_prices
    UNION ALL
    SELECT c.provider, c.model, c.input, c.output, c.cache_read, c.cache_write
    FROM catalog_prices c
    WHERE NOT EXISTS (SELECT 1 FROM model_prices m WHERE m.provider = c.provider AND m.model = c.model)
), kinds AS (
    SELECT e.id,
           GREATEST(e.tokens_input, 0)::double precision AS tin,
           (GREATEST(e.tokens_output, 0) + GREATEST(e.tokens_reasoning, 0))::double precision AS tout,
           GREATEST(e.tokens_cache_read, 0)::double precision AS tread,
           GREATEST(e.tokens_cache_write, 0)::double precision AS twrite,
           GREATEST(e.tokens_input, 0) + GREATEST(e.tokens_output, 0) + GREATEST(e.tokens_reasoning, 0)
               + GREATEST(e.tokens_cache_read, 0) + GREATEST(e.tokens_cache_write, 0) AS classified,
           GREATEST(e.tokens_total, 0) AS total,
           p.provider IS NOT NULL AS has_price,
           p.input, p.output, p.cache_read, p.cache_write
    FROM usage_events e
    LEFT JOIN price p ON p.provider = e.provider AND p.model = e.model
)
UPDATE usage_events e SET
    priced               = k.has_price AND k.classified > 0,
    unpriced_tokens      = CASE WHEN k.has_price THEN GREATEST(k.total - k.classified, 0)
                                ELSE GREATEST(k.total, k.classified) END,
    cost_input_usd       = CASE WHEN k.has_price AND k.classified > 0 THEN k.tin * k.input / 1e6 ELSE 0 END,
    cost_output_usd      = CASE WHEN k.has_price AND k.classified > 0 THEN k.tout * k.output / 1e6 ELSE 0 END,
    cost_cache_read_usd  = CASE WHEN k.has_price AND k.classified > 0 THEN k.tread * k.cache_read / 1e6 ELSE 0 END,
    cost_cache_write_usd = CASE WHEN k.has_price AND k.classified > 0 THEN k.twrite * k.cache_write / 1e6 ELSE 0 END,
    cache_savings_usd    = CASE WHEN k.has_price AND k.classified > 0
                                THEN (k.tread * (k.input - k.cache_read) - k.twrite * (k.cache_write - k.input)) / 1e6
                                ELSE 0 END
FROM kinds k
WHERE e.id = k.id;

-- +goose Down
ALTER TABLE usage_events
    DROP COLUMN priced,
    DROP COLUMN unpriced_tokens,
    DROP COLUMN cache_savings_usd,
    DROP COLUMN cost_cache_write_usd,
    DROP COLUMN cost_cache_read_usd,
    DROP COLUMN cost_output_usd,
    DROP COLUMN cost_input_usd;
