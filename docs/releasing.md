# Container images

Two workflows publish `slowshield` and `slowshield-caddy`, each from a GitHub environment that holds the
registry settings:

| Workflow | Trigger | Environment | Registry (`IMAGE_PREFIX`) | Tags |
|---|---|---|---|---|
| `dev-images.yml` | push to `main` | `development` | `registry.squirro.com/slowshield-dev` (Harbor, private) | `main`, `sha-<commit>` |
| `release.yml` | tag `vX.Y.Z` | `production` | `ghcr.io/squirro` (GHCR, public) | `X.Y.Z`, `X.Y`, `X`, `latest` |

Both build amd64 and arm64 on native GitHub-hosted runners without build caches, push by digest with an SBOM
and a provenance attestation, then create the multi-arch tags. Pull requests build the images too (`ci.yml`)
but never push them.

The release additionally runs, per architecture, the end-to-end tests, the performance gate against the
previous `latest` (skipped for the first release) and the observability smoke test. Nothing is tagged unless
both architectures pass, and only then is the GitHub Release created with the CHANGELOG section and the
performance reports.

## Setup

### `development`: Harbor

`development` is restricted to the `main` branch, so only builds of `main` can use the Harbor credentials.

1. In Harbor, the private project `slowshield-dev`, with a tag retention policy (for example: keep the 30 most
   recent `sha-*`, always keep `main`).
2. A robot account with push and pull on that project.
3. GitHub → Settings → Environments → `development`:

   | Kind | Name | Value |
   |---|---|---|
   | Variable | `IMAGE_PREFIX` | `registry.squirro.com/slowshield-dev` |
   | Variable | `REGISTRY_USERNAME` | the robot's full name (`robot$…`) |
   | Secret | `REGISTRY_PASSWORD` | the robot's secret |

### `production`: GHCR

1. GitHub → Settings → Environments → `production`:
   - Variable `IMAGE_PREFIX` = `ghcr.io/squirro`. No username or password: the release jobs push with their
     own `GITHUB_TOKEN` (`packages: write`).
   - Deployment branches and tags: *Selected*, with the branch `main` (website deploys) **and the tag rule
     `v*`** (releases).
2. Organisation settings → Packages: allow public packages.
3. After the first release, set the packages `slowshield` and `slowshield-caddy` to **Public** (package page →
   Package settings → Change visibility) and link them to the repository.
4. Rules → Rulesets → New tag ruleset for `v*`: only maintainers may create, update or delete release tags.

## Cutting a release

1. Merge everything for the release into `main` and wait for CI to pass there.
2. In `CHANGELOG.md`, move the `[Unreleased]` entries under `## [X.Y.Z] - YYYY-MM-DD` (the release notes are
   taken from that section), commit and push to `main`.
3. Tag and push:

   ```sh
   git switch main && git pull
   git tag -a vX.Y.Z -m "SlowShield X.Y.Z"
   git push origin vX.Y.Z
   ```

4. Follow Actions → Release (about 30–60 minutes).
5. Check:

   ```sh
   docker buildx imagetools inspect ghcr.io/squirro/slowshield:X.Y.Z   # both platforms + attestations
   docker run --rm -p 127.0.0.1:8080:8080 ghcr.io/squirro/slowshield:X.Y.Z
   ```

## When something fails

- **build or verify fails**: nothing was tagged. Fix on `main` and release the next patch version. Do not move
  a pushed tag; the digests already pushed are harmless without tags.
- **A bad release got through**: point `latest` (and `X.Y`, `X`) back at the previous version, then fix
  forward with a new patch release:

  ```sh
  for repo in slowshield slowshield-caddy; do
    docker buildx imagetools create --tag "ghcr.io/squirro/${repo}:latest" "ghcr.io/squirro/${repo}:<previous X.Y.Z>"
  done
  ```
