# Security model

## What SlowShield protects against

| Threat | Control |
|---|---|
| Freshly published malicious release (account takeover, typosquat, dependency confusion bait) | release-age delay; known-malware blocklist |
| Known malicious package or version | OSV + GitHub malware feeds, `451` everywhere, never bypassed by fail-open |
| Lockfile / direct-URL installs skipping the index | downloads are gated by the same policy (`403`); unknown files are `404` |
| Registry, CDN or MITM serving altered bytes | sha256 / blake2b-256 / sha512 / sha1 verification against the registry's digests, plus trust-on-first-use fingerprints; the final chunk is withheld until verification passes |
| Cache poisoning | content-addressed cache written only after verification; npm tarball URLs from config, never from request headers; `Vary: Accept` |
| SSRF / open proxy | upstream hosts fixed by configuration; redirects followed only within them; npm pass-through limited to an allow-list |
| Path traversal | strict regexes on raw paths, percent-encoded `..`/`/`/NUL rejected |
| Decompression bombs / huge documents | size caps on decompressed metadata (50 MB PyPI, 200 MB npm) and OSV archives |
| Stored XSS via feed text | Jinja2 autoescaping everywhere, `https://`-only links, strict CSP without `unsafe-inline`/`unsafe-eval` |
| CSV formula injection in exports | cells starting with `= + - @` are neutralised |

Not in scope: vulnerabilities (CVEs) in non-malicious packages, license compliance, and malicious code that
stays undetected for longer than your delay.

## Hardening of the deployment

* **Images**: Amazon Linux 2023 only (builder stages too); runtime is `FROM scratch` with an AL2023 RPM
  rootfs: no shell, no package manager, RPM database kept so scanners (Aikido, Trivy, Grype) can inventory
  it. Base images pinned by digest; Python dependencies locked with hashes.
* **Runtime**: non-root UID/GID 65532, read-only root filesystem, `/data` the only writable volume,
  `/tmp` a small `noexec` tmpfs, all capabilities dropped, `no-new-privileges`, default seccomp, memory/PID
  limits; Kubernetes manifests meet the *restricted* Pod Security Standard, with a default-deny
  NetworkPolicy (egress: DNS, HTTPS, OTLP).
* **TLS** (Caddy): TLS 1.3 only by default; X25519MLKEM768 hybrid post-quantum key exchange first;
  ECDSA P-256 certificates; HTTP/3; HSTS; `strict_sni_host`; no `Server` header. Certificates via ACME,
  mounted files or Caddy's internal CA.
* **Secrets**: GitHub token via `GITHUB_TOKEN_FILE` (Docker/Podman/Kubernetes secrets), never baked into
  images or logged (log fields named like tokens are redacted).
* **UI**: read-only; no authentication in this release — restrict it at the network level, or put an
  authenticating proxy (OIDC/SAML/Tailscale) in front of `/` and `/ui/` while leaving `/pypi`, `/npm`
  (or the per-ecosystem hosts) open to clients.

## Privacy

Client IP addresses are stored only on security events (blocked, tampered, fail-open, too-new downloads),
taken from `X-Forwarded-For` only when the peer is a trusted proxy, and erased after
`client_ip_retention_days` (default 30). Set `record_client_ip = false` to never store them.

## Supply chain of SlowShield itself

`uv.lock` with hashes; GitHub Actions pinned by commit SHA and audited by zizmor (pedantic persona);
release builds run without shared caches; images carry SBOM and SLSA provenance attestations; Dependabot
updates everything with a 7-day cooldown.
