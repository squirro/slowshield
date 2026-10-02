# SlowShield observability Helm chart

Grafana Alloy, Prometheus, Loki, Tempo and Grafana with the SlowShield datasources, dashboards and alert
rules. It is the Kubernetes counterpart of `deploy/docker/compose.observability.yaml` and
`deploy/podman/observability/`, built from the same configs in [`observability/`](../../../observability/README.md).

```sh
helm install obs deploy/helm/slowshield-observability \
  --namespace observability --create-namespace \
  --set slowshieldNamespace=slowshield

# point SlowShield at Alloy and expose Caddy's metrics
helm upgrade slowshield deploy/helm/slowshield -n slowshield --reuse-values \
  --set telemetry.otlpEndpoint=http://obs-slowshield-observability-alloy.observability.svc.cluster.local:4318 \
  --set caddy.metrics=true

kubectl -n observability port-forward svc/obs-slowshield-observability-grafana 3000:3000
```

The install notes print the Grafana admin password command. `helm test obs -n observability` asks
Grafana to health-check its Prometheus, Loki and Tempo datasources. That also proves the
NetworkPolicies let the traffic through.

## Design

* **Same configs as Compose and Podman.** `files/` holds copies of `observability/` made by
  `uv run python observability/sync.py`. CI fails if they drift. Edit the originals, never the copies.
  The templates only point the configs' Compose hostnames (`prometheus:9090`, `loki:3100`,
  `tempo:3200`) at this release's Services.
* **One replica each, `Recreate`, ReadWriteOnce volumes.** This is a single-node stack sized for one
  SlowShield instance. A second Alloy replica would scrape Caddy and tail its log twice. The PVCs carry
  `helm.sh/resource-policy: keep`.
* **Least privilege.** Every pod runs as its image's own non-root user with a read-only root
  filesystem, no capabilities and `RuntimeDefault` seccomp (Pod Security "restricted"). Only Alloy
  gets a service-account token, bound to a Role in the SlowShield namespace (`pods` get/list/watch,
  `pods/log` get). Nothing is cluster-wide: its `k8sattributes` processor watches only that namespace.
* **Caddy without hostPath.** Alloy discovers SlowShield pods (`app.kubernetes.io/name=slowshield`)
  through the Kubernetes API, scrapes the `caddy-metrics` port and reads the Caddy container's access
  log from the pod log API.
* **NetworkPolicies** (`networkPolicy.enabled`, default on): Alloy accepts OTLP only from SlowShield
  pods (`alloy.otlpFrom`). Prometheus, Loki and Tempo accept only their in-stack clients. Egress is DNS,
  the in-stack backends, Caddy's metrics port, the Kubernetes API for Alloy (`networkPolicy.apiServer`)
  and HTTPS for Grafana's alert webhooks (`networkPolicy.grafanaEgress`).
* **Images** are the official upstream ones pinned by tag and digest. The pins come from
  `observability/images.env` through `sync.py`, not from Dependabot.

## Key values

| Value | Default | |
|---|---|---|
| `slowshieldNamespace` | release namespace | Where the SlowShield release runs (discovery and Role) |
| `grafana.admin.existingSecret` | `""` | Admin password Secret. Otherwise one is generated and kept across upgrades. Set this with GitOps tools that render offline (Argo CD), since `lookup` cannot see the cluster there |
| `grafana.rootUrl` | `""` | Public URL when Grafana sits behind an Ingress (links in notifications) |
| `grafana.service.type` | `ClusterIP` | |
| `grafana.ingressFrom` | `[]` (anyone) | NetworkPolicy peers allowed to reach the UI |
| `alerting.existingSecret` / `.webhookUrl` | `""` | Alert receiver (Slack/Mattermost/Teams webhook, Alertmanager, …). Without one, alerts show in Grafana only |
| `alloy.otlpFrom` | SlowShield pods, any namespace | Who may send OTLP |
| `prometheus.retention` / `.retentionSize` | `15d` / `""` | Loki and Tempo keep 15 days (set in their configs) |
| `{prometheus,loki,tempo,grafana}.persistence.*` | enabled, 20/10/10/2 Gi | `enabled: false` uses an emptyDir |
| `networkPolicy.apiServer` | TCP 443 and 6443 to anywhere | Narrow it with an `ipBlock` for your control plane |

Already running a Grafana stack? Skip this chart, set `telemetry.otlpEndpoint` to your collector and
import `observability/grafana/dashboards/*.json`. The dashboards select their datasources through
template variables.
