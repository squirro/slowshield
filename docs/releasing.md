# Releasing the container images

`.github/workflows/release.yml` builds and publishes `registry.squirro.com/slowshield/slowshield` and
`registry.squirro.com/slowshield/slowshield-caddy` when a tag `vX.Y.Z` is pushed:

1. **build** (amd64 and arm64, native runners, no build caches): push each image by digest, with an SBOM and
   provenance attestation.
2. **verify** (per architecture): pull the candidate by digest, run the end-to-end tests, the performance gate
   against the previous `latest` (skipped for the first release) and the observability smoke test.
3. **publish**: create the multi-arch manifests and tags `X.Y.Z`, `X.Y`, `X` and `latest`, then the GitHub
   Release with the CHANGELOG section and the performance reports.

Nothing is tagged `latest` unless both architectures pass every check. Pull requests and `main` build the
images too (`ci.yml`), but never push them.

## One-time setup

### Harbor (registry.squirro.com)

1. Make sure the project `slowshield` exists. Keep it private until the open-source release.
2. In the project, create a robot account (Robot Accounts → New Robot Account), for example `github-release`,
   with **push and pull** on the project's repositories and no expiry, or a long one with a reminder.
3. Copy its full name (Harbor shows it as `robot$slowshield+github-release`) and its secret.

### GitHub (squirro/slowshield → Settings)

1. **Environments → New environment** `harbor`:
   - Deployment branches and tags: *Selected*, add the tag rule `v*` (only release tags can use the secret).
   - Environment variable `HARBOR_USERNAME` = the robot's full name.
   - Environment secret `HARBOR_REGISTRY_TOKEN` = the robot's secret.
   - Optional: Required reviewers, so a person approves each release before anything is pushed.
2. **Rules → Rulesets → New tag ruleset**, target `v*`: restrict creation, update and deletion to maintainers,
   so a release tag can neither be created by anyone else nor moved afterwards.

The workflow uses GitHub-hosted runners only (`ubuntu-24.04`, `ubuntu-24.04-arm`); nothing to install.

## Cutting a release

1. Merge everything for the release into `main` and wait for CI to pass there.
2. In `CHANGELOG.md`, move the `[Unreleased]` entries under a new heading `## [X.Y.Z] - YYYY-MM-DD`
   (the release notes are taken from that section), commit and push to `main`.
3. Tag the commit and push the tag:

   ```sh
   git switch main && git pull
   git tag -a vX.Y.Z -m "SlowShield X.Y.Z"
   git push origin vX.Y.Z
   ```

4. Follow the run under Actions → Release (about 30–60 minutes). If you configured reviewers, approve the
   `harbor` environment when asked.
5. Check the result:

   ```sh
   docker buildx imagetools inspect registry.squirro.com/slowshield/slowshield:X.Y.Z   # both platforms + attestations
   docker run --rm -p 127.0.0.1:8080:8080 registry.squirro.com/slowshield/slowshield:X.Y.Z
   ```

## When something fails

- **build or verify fails**: nothing was tagged. Fix on `main`, then release the next patch version. Do not
  move a tag that was pushed; the digests already pushed are harmless without tags.
- **A bad release got through**: point `latest` (and `X.Y`, `X`) back at the previous version:

  ```sh
  for repo in slowshield slowshield-caddy; do
    docker buildx imagetools create --tag "registry.squirro.com/slowshield/${repo}:latest" \
      "registry.squirro.com/slowshield/${repo}:<previous X.Y.Z>"
  done
  ```

  then fix forward with a new patch release.
