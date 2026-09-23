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
4. Only after both images are published, bump the pins in the backend repository in one commit on `main`: the tag of both images (`yoonaowo/llm-proxy-backend` and `yoonaowo/llm-proxy-frontend`) in `docker-compose.yml` and in `docker-compose.minimal.yml`, and the copy of `docker-compose.minimal.yml` shown inline in `README.md`.

   The image tags in the two compose files (and the README's copy of the minimal one) are the only place a release version is written. No README prose names a version and needs a bump: the README downloads the compose files from `main` and sends readers to the releases and Docker Hub tags pages for the current release. `scripts/check-readme-compose.sh` fails if the README's copy differs from `docker-compose.minimal.yml`.

Why the pins lag the tag: the README and the compose files on `main` are what users copy (the README's `curl` commands download from `main`), and every version they name must already exist on Docker Hub. A tag's images appear only after its CI run passes; pins bumped before that would send users to a version that cannot be pulled, or to one whose release failed. So a tag's own compose files still name the previous release, and `main` names the new one only after its images are published.

Pushes to `main` publish `edge` and `sha-<commit>` only; `latest` moves only with a version tag.

## CI security model

- Publishing runs only in the `publish` job, only on `push` events to `main` or `v*` tags, and only after the tests pass. It is the only job that declares the `dockerhub` environment, which holds the Docker Hub token and whose deployment policy admits only the `main` branch and `v*` tags.
- Pull requests, forks included, run the tests and a two-platform image build with no secrets, no registry login and no push. The workflow uses neither `pull_request_target` nor `workflow_run`, so PR code never runs next to a secret.
- The workflow token is read-only (`permissions: contents: read`), and every action is pinned to a full commit SHA with its version in a comment.
