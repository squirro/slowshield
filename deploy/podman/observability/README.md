# Observability stack on rootless Podman (Quadlet)

Grafana Alloy, Prometheus, Loki, Tempo and Grafana next to the SlowShield pod from
[`../quadlet`](../quadlet), all rootless, read-only, without capabilities and with `no-new-privileges`.

| Unit | Role | Port |
|---|---|---|
| `slowshield-alloy.container` | OTLP receiver (app + Caddy), scrapes Caddy metrics, tails Caddy access logs | 4317/4318 (internal) |
| `slowshield-prometheus.container` | Metrics (OTLP + remote-write receiver), 15 days | 9090 (internal) |
| `slowshield-loki.container` | Logs (OTLP), 15 days | 3100 (internal) |
| `slowshield-tempo.container` | Traces + span-metrics/service graph, 15 days | 3200 (internal) |
| `slowshield-grafana.container` | Dashboards & alerting | **127.0.0.1:3000** |
| `slowshield-telemetry.network` | Internal network (no egress) shared by the stack and the SlowShield pod | |
| `*.volume` | Persistent data for each component | |
| `slowshield.pod.d/`, `slowshield.container.d/`, `slowshield-caddy.container.d/` | Drop-ins that attach the pod to the telemetry network and switch on OTLP, Caddy metrics, tracing and access logs | |

Images are the official ones pinned by digest ([`observability/images.env`](../../../observability/images.env)),
so `AutoUpdate=` is deliberately not used for them: bump the digests in the repository instead.

Every container runs as its image's own user with `UserNS=keep-id:uid=<that user>`, so volume files
belong to the deploying account on the host (like the SlowShield pod) and Alloy can read Caddy's access
log on the shared `slowshield-caddy-logs` volume.

## Install

Install the SlowShield pod first ([`../README.md`](../README.md)), then as the same user:

```sh
# configs and dashboards (single source of truth: observability/ in this repository)
mkdir -p ~/.config/slowshield/observability
cp -r ../../../observability/{alloy,prometheus,loki,tempo,grafana} ~/.config/slowshield/observability/

# units + drop-ins
cp -r ./*.container ./*.volume ./*.network ./*.d ~/.config/containers/systemd/

# Grafana admin password (stored as a Podman secret, mounted read-only)
openssl rand -base64 24 | tr -d '/+=' | tee /dev/stderr | podman secret create slowshield_grafana_admin_password -

systemctl --user daemon-reload
systemctl --user restart slowshield-pod.service      # picks up the drop-ins (telemetry network, OTLP)
systemctl --user start slowshield-alloy.service slowshield-prometheus.service \
  slowshield-loki.service slowshield-tempo.service slowshield-grafana.service
```

Open <http://127.0.0.1:3000> (user `admin`) — or tunnel it: `ssh -L 3000:127.0.0.1:3000 host`.
The **SlowShield** folder holds six dashboards (Overview, Security, Upstream & Performance, Feeds,
Caddy / TLS, Traces) and the alert rules described in [`observability/README.md`](../../../observability/README.md).

## Alerts

Grafana sends notifications to the `slowshield-default` webhook contact point. Point it at your
receiver (Slack/Mattermost/Teams incoming webhook, Alertmanager, …):

```sh
systemctl --user edit slowshield-grafana.service   # or a slowshield-grafana.container.d/ drop-in:
# [Container]
# Environment=SLOWSHIELD_ALERT_WEBHOOK_URL=https://hooks.example.com/...
```

## Notes

* The Caddy access log file is created by Caddy; with `keep-id` both containers act as the same host
  user, so Alloy can read it whatever the file mode is.
* Caddy metrics are scraped at `slowshield:9180` (every container of a Podman pod answers to the pod
  name on its networks). Override with `Environment=CADDY_METRICS_TARGET=…` in a drop-in for Alloy.
* Port 3000 already used? Change `PublishPort=` in `slowshield-grafana.container`.
* Remove everything: stop the services, delete the units, then
  `podman volume rm slowshield-{alloy,prometheus,loki,tempo,grafana}-data` and
  `podman secret rm slowshield_grafana_admin_password`.
