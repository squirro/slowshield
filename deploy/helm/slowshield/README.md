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
| `ecosystems.{pypi,npm,go,maven,cargo,nuget,composer,oci}.enabled` | `true` | Serve that ecosystem at `/pypi/simple/`, `/npm/`, `/go/`, `/maven/`, `/cargo/`, `/nuget/`, `/composer/` or `/v2/` (container images) |
| `ecosystems.{pypi,npm}.hostnames` | `[]` | Deprecated (removed in 0.1): per-ecosystem host routing; clients use `/pypi/simple/` and `/npm/` |
| `config` | see values.yaml | `config.toml` (delays, exceptions, cache, feeds) |
| `feeds.github.existingSecret` / `.token` | `""` | GitHub Advisory feed token (feed stays off without it) |
| `telemetry.otlpEndpoint` | `""` | OTLP/HTTP endpoint (e.g. Alloy); also enables Caddy tracing |
| `caddy.metrics` | `false` | Prometheus metrics on container port `caddy-metrics` (9180) |
| `service.type` | `ClusterIP` | `LoadBalancer` exposes TCP 80/443 + UDP 443 |
| `persistence.data.size` | `25Gi` | Database + artifact cache (`config` → `cache.artifacts_max_gb`) |
| `persistence.ociLayers.enabled` | `false` | Own volume for the container layer store (`config` → `upstreams.oci.layer_cache_gb`); `ephemeral: true` makes it an `emptyDir` of `size` |
| `image.digest` / `caddy.image.digest` | `""` | Pin immutable digests |
| `shieldwall.role` | `""` | `""` keeps the stored role; `standalone` leaves the wall explicitly; `leader` makes this release a shield wall leader ([docs/design/shieldwall.md](../../../docs/design/shieldwall.md)) |
| `shieldwall.joinSecret` / `.joinSecretKey` | `""` / `join` | A Secret with a follower's join string (from `slowshield wall invite` on the leader) |
| `shieldwall.name` / `.location` / `.labels` | `""` / `""` / `{}` | How the leader shows and filters this follower |
| `shieldwall.leaderEgress` | `[]` | Network policy egress rules to a leader on a private network |
| `shieldwall.leaderCaSecret` / `.leaderCaSecretKey` | `""` / `ca.crt` | A Secret with the CA that signed the leader's certificate (its Caddy's internal CA, the chart's default `tls.mode`). A follower needs this or `leaderPubliclyTrusted`: the chart refuses a `joinSecret` without one of them |
| `shieldwall.leaderPubliclyTrusted` | `false` | `true` when the leader's certificate is publicly trusted (`tls.mode=acme`), so the follower needs no CA |
| `shieldwall.confirm` | `ui` | `auto` joins without the click on the Shield wall page (automated installs) |
| `hostAliases` | `[]` | `/etc/hosts` entries for the pod, e.g. a tailnet-only leader's name pointed at an in-cluster egress proxy ([docs/tailscale.md](../../../docs/tailscale.md)) |

`helm test slowshield` runs a pod (the SlowShield image itself) that checks `/healthz` through the Service.

## A shield wall follower

A follower pairs on its first start and keeps its leader in its volume; it ignores the join string from then on.

1. **On the leader**, right before installing (the string works once, for up to 60 minutes):
   `slowshield wall invite --name us-east --location Virginia --minutes 60 --quiet`
2. **Store it**: `kubectl -n slowshield create secret generic slowshield-join --from-literal=join='ssj1:...'`
3. **Check the storage class**: `kubectl get storageclass`. A dry run doesn't notice a class that doesn't exist, and a
   PVC's class can't be changed later: the claims stay Pending, and fixing it means deleting them (and, with Flux,
   the failed release) so they're created again.
4. **Install** with `shieldwall.joinSecret`, `shieldwall.confirm=auto`, and either `shieldwall.leaderPubliclyTrusted`
   or `shieldwall.leaderCaSecret`.
5. **Check** `kubectl -n slowshield exec deploy/slowshield -c slowshield -- slowshield wall status` (leader `active`)
   and `slowshield wall members` on the leader.

Examples in [`examples/`](examples/):

| File | |
|---|---|
| [`follower-values.yaml`](examples/follower-values.yaml) | A follower of a tailnet-only leader that also serves a Tailscale Service |
| [`tailnet-leader-egress.yaml`](examples/tailnet-leader-egress.yaml) | Tailscale operator egress to a leader that is only on the tailnet |
| [`tailscale-service.yaml`](examples/tailscale-service.yaml) | Serves the release as a Tailscale Service shared with `tailscale serve` hosts |
| [`flux.yaml`](examples/flux.yaml) | Flux: the chart straight from a release tag (it isn't in a chart registry) |

[docs/tailscale.md](../../../docs/tailscale.md) explains the Tailscale parts.

The observability stack (Alloy, Prometheus, Loki, Tempo, Grafana with dashboards) is a separate
chart: `deploy/helm/slowshield-observability`.
