-- +goose Up
-- The vendor_credentials_import row is the only evidence that v0.2.0 imported
-- the credential files an earlier release kept in the grants volume. A database
-- with users but no marker skipped that import: booting it would serve with no
-- vendor accounts while the release notes say to remove the volume, their only
-- copy, so it is refused. A fresh install passes, because migrations run before
-- the bootstrap administrator is created and users is still empty.
-- +goose StatementBegin
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM settings WHERE key = 'vendor_credentials_import')
       AND EXISTS (SELECT 1 FROM users) THEN
        RAISE EXCEPTION 'upgrade to v0.2.0 and start it once before this one';
    END IF;
END $$;
-- +goose StatementEnd

DELETE FROM settings WHERE key = 'vendor_credentials_import';

-- +goose Down
-- The marker is not restored: nothing reads it any more.
SELECT 1;
