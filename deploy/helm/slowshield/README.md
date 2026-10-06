# SlowShield Helm chart

Deploys SlowShield with an optional Caddy sidecar that terminates TLS (TLS 1.3, HTTP/3, ACME).

```sh
helm install slowshield deploy/helm/slowshield \
  --namespace slowshield --create-namespace \
  --set hostnames='{slowshield.example.com}' \
  --set service.type=LoadBalancer \
  --set tls.mode=acme --set tls.acme.email=ops@example.com
```

## Design

* **One replica, `Recreate`.** State (SQLite + verified artifact cache) lives on a ReadWriteOnce
  PVC with a single writer. There is deliberately no PodDisruptionBudget: with one replica a PDB
  could only block node drains. Scale vertically (`workers`, `resources`).
* **Caddy sidecar** (`caddy.enabled=true`, default): SlowShield listens on `127.0.0.1:8081` only and
  is reachable exclusively through Caddy. Probes use the exec form of `slowshield healthcheck`
  (the images have no shell). Caddy's plain-HTTP port answers `/healthz` (proxied to SlowShield)
  for load-balancer health checks and redirects everything else to HTTPS.
* **Your own Ingress/Gateway** (`caddy.enabled=false`): SlowShield listens on 8080 and the Service
  is plain HTTP. Ingress controller addresses must fall within SlowShield's `trusted_proxies`
  (private ranges by default) for client IPs to be recorded correctly.
* **Pod Security "restricted"**: non-root UID/GID 65532, read-only root filesystem, all capabilities
  dropped, `RuntimeDefault` seccomp, no service-account token, in-memory `/tmp`.
* **NetworkPolicy**: ingress only to the client ports (and 9180 for Caddy metrics when enabled),
  egress only to DNS, public HTTPS (registries, feeds, ACME) and, if configured, the OTLP collector.

## TLS modes

| `tls.mode` | Certificates | Notes |
|---|---|---|
| `internal` | Caddy's own CA | Clients must trust the root; see the install NOTES for how to export it. |
| `acme` | Let's Encrypt (or `tls.acme.ca`) | Hostnames must resolve to the Service; 80/443 reachable. Certificates persist on the `-caddy` PVC. |
| `files` | `tls.existingSecret` (`kubernetes.io/tls`) | E.g. from cert-manager or an internal CA. |

## Key values

| Value | Default | |
|---|---|---|
| `hostnames` | `[slowshield.example.com]` | Caddy site addresses |
| `publicUrl` | `https://<first hostname>` | Used for npm tarball URLs and setup snippets |
| `ecosystems.{pypi,npm,go,maven}.enabled` | `true` | Serve that ecosystem at `/pypi/simple/`, `/npm/`, `/go/` or `/maven/` |
| `ecosystems.{pypi,npm}.hostnames` | `[]` | Deprecated (removed in 0.1): per-ecosystem host routing; clients use `/pypi/simple/` and `/npm/` |
| `config` | see values.yaml | `config.toml` (delays, exceptions, cache, feeds) |
| `feeds.github.existingSecret` / `.token` | `""` | GitHub Advisory feed token (feed stays off without it) |
| `telemetry.otlpEndpoint` | `""` | OTLP/HTTP endpoint (e.g. Alloy); also enables Caddy tracing |
| `caddy.metrics` | `false` | Prometheus metrics on container port `caddy-metrics` (9180) |
| `service.type` | `ClusterIP` | `LoadBalancer` exposes TCP 80/443 + UDP 443 |
| `persistence.data.size` | `25Gi` | Database + artifact cache (`config` → `cache.artifacts_max_gb`) |
| `image.digest` / `caddy.image.digest` | `""` | Pin immutable digests |

`helm test slowshield` runs a pod (the SlowShield image itself) that checks `/healthz` through the Service.

The observability stack (Alloy, Prometheus, Loki, Tempo, Grafana with dashboards) is a separate
chart: `deploy/helm/slowshield-observability`.
