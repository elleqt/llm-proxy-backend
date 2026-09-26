# Releasing

llm-proxy is versioned with [semver](https://semver.org/) (`vX.Y.Z`). The backend and the frontend are released together: both repositories get the same tag, and users run both images at the same version.

## Cut a release

1. Make sure `main` is green in both repositories and each checkout is at the commit to release.
2. Tag both on `main` with the same version and push the tags:

   ```sh
   # in llm-proxy-backend
   git switch main && git pull --ff-only
   git tag -a vX.Y.Z -m vX.Y.Z && git push origin vX.Y.Z
   # in llm-proxy-frontend
   git switch main && git pull --ff-only
   git tag -a vX.Y.Z -m vX.Y.Z && git push origin vX.Y.Z
   ```

3. CI runs the tests on the tag, then publishes `yoonaowo/llm-proxy-backend` and `yoonaowo/llm-proxy-frontend` for `linux/amd64` and `linux/arm64` as `X.Y.Z`, `X.Y`, `latest` (and `X` once the major version is 1 or more), and smoke-tests each platform. Check both runs, then `docker buildx imagetools inspect docker.io/yoonaowo/llm-proxy-backend:X.Y.Z`.
4. Only after both images are published, bump the pins in the backend repository in one pull request to `main`: the tag of both images (`yoonaowo/llm-proxy-backend` and `yoonaowo/llm-proxy-frontend`) in `docker-compose.yml` and in `docker-compose.minimal.yml`, and the copy of `docker-compose.minimal.yml` shown inline in `README.md`.

   The image tags in the two compose files (and the README's copy of the minimal one) are the only place a release version is written. No README prose names a version and needs a bump: the README downloads the compose files from `main` and sends readers to the releases and Docker Hub tags pages for the current release. `scripts/check-readme-compose.sh` fails if the README's copy differs from `docker-compose.minimal.yml`.

Why the pins lag the tag: the README and the compose files on `main` are what users copy (the README's `curl` commands download from `main`), and every version they name must already exist on Docker Hub. A tag's images appear only after its CI run passes; pins bumped before that would send users to a version that cannot be pulled, or to one whose release failed. So a tag's own compose files still name the previous release, and `main` names the new one only after its images are published.

Pushes to `main` publish `edge` and `sha-<commit>` only; `latest` moves only with a version tag.

## Next release: remove the credentials import

<!-- COMPAT(credentials-import): this whole section; the release that completes it deletes it (row 7). -->
The release that moved the vendor accounts' OAuth credentials from files into Postgres keeps, for the upgrade only, a one-shot import from `LLMPROXY_AUTH_DIR` (the `grants` volume) and a tolerance of settings keys that no longer have an effect. The release after it removes them. Every site is tagged `COMPAT(credentials-import)` in code, compose files and README.

| # | What | Where | Next release |
|---|---|---|---|
| 1 | One-shot import | `gateway.ImportFileCredentials` and its tests (`internal/infra/gateway/import.go`, `import_test.go`); its call in `boot.build()`; the e2e test `TestAVendorAccountOutlivesItsCredentialFile` (`test/e2e/credentials_test.go`), whose first boot relies on the import; the `InfoLogger` entry in `.mockery.yaml` and the generated `internal/app/mocks/info_logger.go` (generated files cannot carry the tag), added only for the import tests; the COMPAT paragraph of `canonicalJSON`'s comment (`internal/infra/gateway/credential_store.go`) | delete (the e2e test: delete, or rewrite it to seed the account through the store; the mock: drop `InfoLogger` from `.mockery.yaml` unless something else uses it, then `make generate`) |
| 2 | Import methods of the port | `VendorCredentialRepo.ImportDone` / `Import`, their SQL, `errAlreadyImported` and tests in `postgres/vendorcreds`, the regenerated mock (`make generate`) | delete |
| 3 | Import marker row | `settings` row `vendor_credentials_import` | new migration that first refuses a database which was used but never imported, then deletes the marker: `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM settings WHERE key = 'vendor_credentials_import') AND EXISTS (SELECT 1 FROM users) THEN RAISE EXCEPTION 'upgrade to <this release> and start it once before this one'; END IF; END $$;` followed by `DELETE FROM settings WHERE key = 'vendor_credentials_import';` (name the import release in place of `<this release>`; the `DO` block needs goose's `-- +goose StatementBegin` / `-- +goose StatementEnd`). The marker is the only evidence that the import ran: an installation that skipped the import release has users but no marker, and would otherwise boot with no vendor accounts while its release notes tell it to remove the `grants` volume, their only copy. A fresh install passes the check, because migrations run before the bootstrap administrator is created, so `users` is still empty |
| 4 | `grants` volume | `docker-compose.yml` (the backend's mount, the top-level volume, and the COMPAT comment above `LLMPROXY_RUNTIME_DIR` / `LLMPROXY_AUTH_DIR` in the backend's environment), `docker-compose.minimal.yml`, README compose block (byte-equal) | remove mount and volume; the environment comment keeps only its first three lines |
| 5 | Import wording | README (Upgrading, backup, env table: "import source" on `LLMPROXY_AUTH_DIR`), config.go comment, the import item of the boot paragraph in `AGENTS.md` | keep only "login scratch directory"; Upgrading: `docker volume rm <project>_grants`. Release notes, before that command: an installation on a release before the one with the import must first upgrade to that release and start it once (its log reports how many accounts it imported); only then upgrade further and remove the `grants` volume. Skipping it leaves the accounts unimported, and removing the volume deletes their only copy |
| 6 | Tolerance of legacy inert keys | `save-cooldown-status`, `request-log`, `error-logs-max-files` in `internal/app/settings/settings.go`: the `LoadBootConfig` boot warning (`inertKeyWarning`) and its `log app.Logger` parameter (passed from `boot.build()` and the tests), `refuseInertKeys`' acceptance of a key the stored document already sets with the same value, and `asStored` (the diff's "from" side taken from the stored document), with the stored-document plumbing that feeds only those two: `replacedDocument`, the second (`base`) result of `proposedDocument` and its use in `Update`, and `replacedDocument`'s extra `storedDocument` read for whole-document updates; in `settings_test.go` the tagged `UpstreamDocument(...).Once()` expectations that read serves, in `TestSettingsRefusesAddingOrChangingInertKeys`, `TestSettingsDryRunAppliesAndPersistsNothing`, `TestSettingsApplyPushesThenPersists`, `TestSettingsPushFailurePersistsNothing`, `TestSettingsPersistFailureRestoresRunningConfiguration` and `TestSettingsDiffAndAuditRedactProxyCredentials`, and the one in `TestADrySettingsRunAppliesNothing` (`internal/iface/http/admin_settings_test.go`); the tests `TestSettingsAcceptsInertKeysKeptOrRemoved`, `TestSettingsDiffOmitsUnchangedInertKeys`, `TestSettingsRemovingAnInertKeyIsAChange`, `TestLoadBootConfigWarnsAboutInertKeys`, the helper `keyAttr`, the test constant `inertKeyWarning` and `newSettingsFixture`'s logger mock with its `.Maybe()` `Warn`; the README's **Gateway settings** note | move the keys into `ownedKeys`; delete the warning, the logger parameter, the acceptance rule, `inertKeys`, `inertValues`, `refuseInertKeys`, `asStored`, `replacedDocument`, `proposedDocument`'s `base` result, the tagged `UpstreamDocument` expectations, and those tests and helpers (a refusal test for the keys as owned keys replaces them). Release notes: a document still setting one now stops boot |
| 7 | This checklist | the "Next release: remove the credentials import" section of `RELEASING.md` | delete once rows 1-6 are done |

**Done when** both commands print nothing: no tracked file carries the tag, and no production (non-`_test.go`) Go file uses upstream's file token store.

```sh
git grep -n "COMPAT(credentials-import)"
git grep -n "sdkauth.NewFileTokenStore" -- '*.go' ':!*_test.go'
```

Stays permanently: `CredentialStore`, `LLMPROXY_CREDENTIALS_KEY`, `LLMPROXY_AUTH_DIR` as the login scratch directory, the nil request logger, the `admit()` forcing, and `Update`'s refusal of the inert keys.

## CI security model

- Publishing runs only in the `publish` job, only on `push` events to `main` or `v*` tags, and only after the tests pass. It is the only job that declares the `dockerhub` environment, which holds the Docker Hub token and whose deployment policy admits only the `main` branch and `v*` tags.
- Pull requests, forks included, run the tests and a two-platform image build with no secrets, no registry login and no push. The workflow uses neither `pull_request_target` nor `workflow_run`, so PR code never runs next to a secret.
- The workflow token is read-only (`permissions: contents: read`), and every action is pinned to a full commit SHA with its version in a comment.

## Repository rules

Both repositories have the same rules, including for their owner:

- `main` changes only through pull requests, merged by squash once CI has passed on them: `test`, `image-check` and `pr-title` here, `check`, `image` and `pr-title` in the frontend. Direct pushes, force-pushes and deleting `main` are refused.
- The pull request's title becomes the commit on `main`. Titles follow [Conventional Commits](https://www.conventionalcommits.org): `type(scope)!: description`, with type one of `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`; the required `pr-title` check refuses anything else.
- Release tags `v*` can be created but never moved or deleted: a published version always points at the commit it was built from.
- CI from a first-time outside contributor's pull request waits for the owner's approval; Actions may only use GitHub's and Docker's own actions, pinned by commit SHA.
- Dependabot opens security updates as advisories appear and grouped version updates once a month (see `.github/dependabot.yml`); CodeQL scans every pull request and `main`.
- Vulnerabilities are reported privately, see [SECURITY.md](SECURITY.md).
