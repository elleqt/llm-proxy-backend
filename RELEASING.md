# Releasing

llm-proxy is versioned with [semver](https://semver.org/) (`vX.Y.Z`). The backend and the frontend are released together: both repositories get the same tag, and users run both images at the same version.

## Cut a release

1. Make sure `main` is green in both repositories and each checkout is at the commit to release.
2. Tag both on `main` with the same version and push the tags:

   ```sh
   # in llm-proxy-backend
   git switch main && git pull --ff-only
   git tag -a v0.2.0 -m v0.2.0 && git push origin v0.2.0
   # in llm-proxy-frontend
   git switch main && git pull --ff-only
   git tag -a v0.2.0 -m v0.2.0 && git push origin v0.2.0
   ```

3. CI runs the tests on the tag, then publishes `yoonaowo/llm-proxy-backend` and `yoonaowo/llm-proxy-frontend` for `linux/amd64` and `linux/arm64` as `0.2.0`, `0.2`, `latest` (and `0` once the major version is 1 or more: `X` tags start at `1.0.0`), and smoke-tests each platform. Check both runs, then `docker buildx imagetools inspect docker.io/yoonaowo/llm-proxy-backend:0.2.0`.
4. Only after both images are published, bump the pins in the backend repository in one commit on `main`:
   - `LLMPROXY_VERSION` in `.env.example`;
   - the default `${LLMPROXY_VERSION:-X.Y.Z}` of both images in `docker-compose.yml`, and the same file inline in `README.md`;
   - the README's `curl` URL (`.../llm-proxy-backend/vX.Y.Z/docker-compose.yml`) and its `.env` example.

   `scripts/check-readme-compose.sh` fails if the README's copy of the compose file differs from `docker-compose.yml`.

Why the pins lag the tag: the README on `main` is what users copy, and every version it names must already exist on Docker Hub. A tag's images appear only after its CI run passes; pins bumped before that would send users to a version that cannot be pulled, or to one whose release failed. So a tag's own `docker-compose.yml` still names the previous release as its default, and the README's `.env` example sets `LLMPROXY_VERSION` explicitly.

Pushes to `main` publish `edge` and `sha-<commit>` only; `latest` moves only with a version tag.

## CI security model

- Publishing runs only in the `publish` job, only on `push` events to `main` or `v*` tags, and only after the tests pass. It is the only job that declares the `dockerhub` environment, which holds the Docker Hub token and whose deployment policy admits only the `main` branch and `v*` tags.
- Pull requests, forks included, run the tests and a two-platform image build with no secrets, no registry login and no push. The workflow uses neither `pull_request_target` nor `workflow_run`, so PR code never runs next to a secret.
- The workflow token is read-only (`permissions: contents: read`), and every action is pinned to a full commit SHA with its version in a comment.
