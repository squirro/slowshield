---
name: slowshield
description: Set up and use SlowShield, a self-hosted proxy that holds new package releases back for a few days and refuses known malware, for pip, uv, Poetry, PDM, Pipenv, npm, pnpm, Yarn, Bun, Go, Maven, Gradle, sbt, Coursier, Cargo and container images (Docker, Podman, containerd, Kubernetes, BuildKit). Use when pointing package managers, Dockerfiles, CI or agent sandboxes at a SlowShield instance, when checking that nothing goes around it, or when an install fails with a SlowShield answer (403 or 425 "too new", 451 or "blocked", X-SlowShield-Fail-Open).
license: Apache-2.0
---

# SlowShield

SlowShield sits between package managers and the public registries. A release becomes installable a number of days
after it was published (7 by default); known malware is refused; every download is checked. One instance serves every
ecosystem under its own path:

| Ecosystem | URL on the instance | Reference |
|---|---|---|
| Python (PyPI) | `<base>/pypi/simple/` | [references/python.md](references/python.md) |
| JavaScript (npm) | `<base>/npm/` | [references/javascript.md](references/javascript.md) |
| Go modules | `<base>/go` | [references/go.md](references/go.md) |
| Java (Maven, Gradle, sbt, Coursier) | `<base>/maven/all/` and others | [references/java.md](references/java.md) |
| Rust (Cargo) | `sparse+<base>/cargo/` | [references/rust.md](references/rust.md) |
| Container images | `<base>` as registry server, or `<base-host>/<registry>/<image>` | [references/containers.md](references/containers.md) |

Building container images (base images and every dependency of a build): [references/container-builds.md](references/container-builds.md).
Rules for agents, in full: [references/agents.md](references/agents.md). The references use `https://slowshield.example.com`:
replace it with the real instance.

## Find the instance

1. Look for it before asking: `PIP_INDEX_URL`, `UV_DEFAULT_INDEX`, `npm_config_registry`, `GOPROXY`, `.npmrc`,
   `~/.m2/settings.xml`, `${CARGO_HOME:-~/.cargo}/config.toml`, `/etc/containerd/certs.d/_default/hosts.toml`,
   `/etc/docker/certs.d/_default/hosts.toml`, `~/.docker/certs.d/`, `registries.conf.d`.
2. Otherwise ask the user for its address. `<base>/ui/setup` on the instance shows every setting with the address
   filled in; prefer it over writing settings by hand.
3. No instance and the user wants one on this machine: run a release, never `:latest` (the newest one is on
   https://github.com/squirro/slowshield/releases; pin its digest where you can):
   `docker run -d --rm --name slowshield -p 127.0.0.1:8080:8080 ghcr.io/squirro/slowshield:<release>`, then
   `<base>` is `http://localhost:8080`. Check it with `curl <base>/readyz` (answers `ready`).

## Set it up

Read the reference for each ecosystem the project uses, and apply its settings at the narrowest scope that does the
job: the project's own files when the setting belongs with the code (`.npmrc`, `pyproject.toml`, `Dockerfile`, CI),
the user's home directory or shell profile for a whole machine. Don't overwrite existing configuration: merge into it,
and show the user what changed.

- Lockfiles keep working. npm writes SlowShield's tarball URLs into `package-lock.json`; `uv.lock` records the index
  URL; Cargo.lock doesn't change.
- Also set each package manager's own release age (pip 26.1+, uv 0.9.17+, Poetry 2.4+, PDM 2.27+, npm 11.10+,
  pnpm 10.16+, Yarn 4.10+, Bun 1.3+) to 3 days when the user wants the second layer; check the installed version
  first, older versions fail or ignore the setting. Each reference lists the details.
- In Dockerfiles, use `ARG` with the tool's variable name (`PIP_INDEX_URL`, `UV_DEFAULT_INDEX`,
  `npm_config_registry`, `GOPROXY`) in every stage that installs something; Maven and Cargo need their config file
  written in a `RUN` step.
- Base images come through the container runtime's configuration, not the Dockerfile.

## Check it

- Install one package per ecosystem and confirm it came through SlowShield: its dashboard (`<base>/ui/packages`)
  lists it, and index responses carry `X-SlowShield-Held-Versions`.
- For builds and CI, the strict check is a network where SlowShield is the only thing reachable: anything not
  configured fails instead of going around it (references/container-builds.md).
- `pip config list`, `npm config get registry`, `go env GOPROXY`, `mvn help:effective-settings` show what a tool
  actually uses.

## Handle its answers

| Answer | Meaning | Do |
|---|---|---|
| An older version than expected, or "no matching version" for an exact new one | Newer versions are held (younger than the delay) | Use the newest version that installs. Don't pin the new one. |
| `403` with `{"error":"age_too_new", …}` (PyPI, npm), "is too new" (Go, Cargo, images), `425 Too Early` (Maven, Gradle) | A pinned version is held; `Retry-After` and the message say until when | Use an older version, or tell the user when it becomes available. |
| `451` with the advisory (images: `403`, "is blocked") | Known malware, or blocked by the administrator | Don't install it or a look-alike. Tell the user. |
| `X-SlowShield-Fail-Open: 1` | A brand-new package, no version old enough, served anyway | Check the name is exactly the intended one. |
| `503` with `Retry-After` | The upstream registry is unavailable | Retry later. |

Never go around SlowShield: no `--index-url`, `--extra-index-url` or `--registry` pointing at a public registry, no
`,direct` in `GOPROXY`, no direct registry hosts for images. If something is needed early, the user can ask the
SlowShield administrator for an exception.
