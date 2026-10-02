# SlowShield on rootless Podman (Quadlet)

Two containers in one pod, managed by systemd as an unprivileged user:

| Unit | What |
|---|---|
| `slowshield.pod` | Pod `slowshield`, publishes 8080 (HTTP → HTTPS redirect, ACME HTTP-01) and 8443 TCP+UDP (HTTPS, HTTP/3) |
| `slowshield.container` | SlowShield, bound to `127.0.0.1:8081` inside the pod (only Caddy can reach it) |
| `slowshield-caddy.container` | Caddy TLS edge |
| `*.volume`, `slowshield.network` | Named volumes and the pod network |

Every container runs read-only as UID 65532 with all capabilities dropped, `no-new-privileges`,
a size-capped `noexec` `/tmp`, PID/memory/CPU limits and `AutoUpdate=registry` (same as the AWX role).

`UserNS=keep-id:uid=65532,gid=65532` maps the in-container user to the deploying account:
volume files are owned by you on the host (simple backups), nothing needs a recursive `chown` on
start (the artifact cache can be tens of GB), and the mapping is deterministic across restarts —
unlike `UserNS=auto`, whose range may change when the container is recreated.

## Install

Requirements: Podman ≥ 5.0 (Quadlet `.pod` support), systemd, and a regular user account
(e.g. `slowshield`) with subordinate UIDs (`/etc/subuid`).

```sh
# as root, once
useradd --create-home slowshield
loginctl enable-linger slowshield            # start the user's services at boot
# optional: allow binding 80/443 without root (otherwise clients use :8443)
echo 'net.ipv4.ip_unprivileged_port_start=80' > /etc/sysctl.d/99-unprivileged-ports.conf
sysctl --system

# as the slowshield user
mkdir -p ~/.config/containers/systemd ~/.config/slowshield/certs
cp -r quadlet/. ~/.config/containers/systemd/
cp examples/config.toml examples/slowshield.env ~/.config/slowshield/
$EDITOR ~/.config/slowshield/slowshield.env  # hostnames, TLS mode, public URL

systemctl --user daemon-reload
systemctl --user start slowshield-pod.service
systemctl --user status slowshield.service slowshield-caddy.service
```

If you allowed low ports, change the pod's `PublishPort=` lines to `80:8080` / `443:8443` and set
`SLOWSHIELD_PUBLIC_HTTPS_PORT=443` in `slowshield.env`.

## TLS

`SLOWSHIELD_TLS_MODE` in `slowshield.env`:

* `internal` (default): Caddy's own CA. Export the root for your clients:
  `podman cp slowshield-caddy:/data/caddy/pki/authorities/local/root.crt ./slowshield-root.crt`
  (the image has no shell or `cat`, so use `podman cp`).
* `acme`: Let's Encrypt (or `ACME_CA`) with `ACME_EMAIL`; ports 80/443 must be reachable.
* `files`: put `tls.crt` and `tls.key` into `~/.config/slowshield/certs/`.

## GitHub Advisory feed

```sh
printf %s 'github_pat_…' | podman secret create slowshield_github_token -
cp ~/.config/containers/systemd/slowshield.container.d/github-token.conf.example \
   ~/.config/containers/systemd/slowshield.container.d/github-token.conf
systemctl --user daemon-reload && systemctl --user restart slowshield-pod.service
```

Without it the feed stays off; the UI shows a banner and `slowshield_feed_enabled{reason="missing_token"}` is 0.

## Updates

`AutoUpdate=registry` makes `podman auto-update` pull newer `:latest` images and restart the pod
when they change. Enable the user timer (daily by default):

```sh
systemctl --user enable --now podman-auto-update.timer
# AWX parity: every 15 minutes during working hours
systemctl --user edit podman-auto-update.timer   # [Timer] OnCalendar= / OnCalendar=*-*-* 07..22:00/15:00 UTC
```

## Operations

```sh
journalctl --user -u slowshield.service -f        # JSON logs
podman healthcheck run slowshield-app              # exit 0 when ready
podman volume export slowshield-data > backup.tar  # back up DB + cache (stop the pod for a consistent copy)
```

Observability (Alloy + Grafana stack): see `observability/` in this directory.
