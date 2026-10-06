# Deploying SlowShield

SlowShield ships as two images, both built only from Amazon Linux 2023 RPMs (distroless-style:
no shell, no package manager, RPM database kept for scanners), multi-arch (amd64/arm64), running
as UID 65532 on a read-only root filesystem:

| Image | Role |
|---|---|
| `ghcr.io/squirro/slowshield` | The proxy (Python 3.15, Granian). Listens on 8080, state in `/data`. |
| `ghcr.io/squirro/slowshield-caddy` | TLS edge (Caddy). 8080 HTTP → HTTPS redirect + ACME, 8443 HTTPS (TCP) and HTTP/3 (UDP). |

| Runtime | Directory | Start |
|---|---|---|
| Docker Compose | [`docker/`](docker/) | `cp .env.example .env && docker compose up -d` |
| Rootless Podman (Quadlet + systemd) | [`podman/`](podman/README.md) | `systemctl --user start slowshield-pod` |
| Kubernetes (Helm) | [`helm/slowshield/`](helm/slowshield/README.md) | `helm install slowshield deploy/helm/slowshield` |

Each has an observability variant (Alloy → Prometheus / Loki / Tempo → Grafana with ready-made
dashboards and alerts): `docker/compose.observability.yaml`, `podman/observability/`,
`helm/slowshield-observability/`.

## TLS

Selected with one variable everywhere (`SLOWSHIELD_TLS_MODE` / `tls.mode`):

| Mode | Use when | Configure |
|---|---|---|
| `internal` (default) | Lab, closed networks | Distribute Caddy's root CA (`/data/caddy/pki/authorities/local/root.crt` in the Caddy container) to clients |
| `acme` | Hostnames resolvable from the internet (or an internal ACME CA) | `ACME_EMAIL`, optional `ACME_CA` |
| `files` | Certificates from your own PKI / cert-manager | `TLS_CERT_FILE`, `TLS_KEY_FILE` (Compose/Podman) or `tls.existingSecret` (Helm) |

**Local testing:** with `SLOWSHIELD_LOCAL_HTTP=on` (the Compose default) Caddy also answers
`http://localhost`, `http://127.0.0.1` and `http://[::1]` over plain HTTP, so pip, uv, npm, go, Maven and cargo on the same machine
work without trusting the internal CA. Requests for any other hostname are still redirected to HTTPS. Turn it
off on a shared server; Podman and Helm leave it off.

Defaults: TLS 1.3 only (`TLS_MIN_VERSION=1.2` re-enables 1.2 with ECDHE+AEAD suites only), Caddy's
default key exchange groups (hybrid post-quantum X25519MLKEM768, X25519, P-256), ECDSA P-256
certificates for ACME, HTTP/3, HSTS (2 years), `strict_sni_host`, no `Server` header, request
bodies limited to 16 KB (10 MB for `npm audit`), only `GET`/`HEAD` (+ `POST` for `npm audit`).

## Pointing clients at it

```sh
pip config set global.index-url https://slowshield.example.com/pypi/simple/
export UV_DEFAULT_INDEX=https://slowshield.example.com/pypi/simple/
npm config set registry https://slowshield.example.com/npm/
```

The UI's **Setup** page shows the exact snippets for your hostnames (pip, uv, Poetry, PDM, Pipenv,
npm, pnpm, Yarn, Bun).

## Building the images

```sh
docker buildx build --file containers/slowshield/Dockerfile -t slowshield:dev .
docker buildx build --file containers/caddy/Dockerfile      -t slowshield-caddy:dev .
# free-threaded interpreter
docker buildx build --file containers/slowshield/Dockerfile --build-arg PYTHON_VARIANT=3.15t -t slowshield:dev-ft .
# release builds: no BuildKit cache mounts
docker buildx build --file containers/slowshield/Dockerfile --build-arg BUILD_CACHE=off ...
```

Caddy's version and SHA-512 sums are pinned in `containers/caddy/Dockerfile`; update them with
`uv run python containers/caddy/bump_caddy.py --write` (verifies the release's cosign signature and,
by default, only picks releases older than 7 days, in keeping with SlowShield's own policy).

## End-to-end tests

```sh
docker buildx build --load -f containers/slowshield/Dockerfile   -t slowshield:ci .
docker buildx build --load -f containers/caddy/Dockerfile        -t slowshield-caddy:ci .
docker buildx build --load -f containers/fakeupstream/Dockerfile -t slowshield-fakeupstream:ci .
E2E=1 uv run pytest -m e2e tests/e2e
```

The suite brings up `docker/compose.yaml` + `docker/compose.e2e.yaml` (SlowShield wired to the
deterministic fake registry) under a unique project name and checks hardening, TLS/HTTP/2, real
`uv` and `npm` installs, age gating, the blocklist, tamper aborts and the artifact cache.
