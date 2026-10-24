# Tailscale

SlowShield doesn't need Tailscale, but runs well on a tailnet. This page covers two setups, both in production use:

- **One name for many instances**: every instance serves the same Tailscale Service, and clients use one URL.
- **A follower whose leader is only on the tailnet** ([shield wall](design/shieldwall.md)): how it reaches the leader
  from a container or a Kubernetes cluster.

## One Tailscale Service for many instances

Run SlowShield in several places and put all of them behind one
[Tailscale Service](https://tailscale.com/docs/features/tailscale-services), `svc:slowshield`. Clients use
`https://slowshield.<your-tailnet>.ts.net`. Tailscale issues the certificate for that name; nothing is exposed to
the internet.

### Prerequisites

- **The Service**, defined in the admin console (Services) or through the API, with endpoint `tcp:443`. The policy
  file can't create it.
- **Tailscale 1.86 or later** on every host that serves it.
- **A tag on every host**, for example `tag:slowshield`. A host signed in as a user can't serve a Service.
- **HTTPS certificates** enabled for the tailnet.
- **Policy**: auto-approve the tagged hosts and let clients use the Service. `svc:` destinations go in `grants`,
  not `acls`:

```jsonc
"tagOwners": {
  "tag:slowshield": ["autogroup:admin"]
},
"autoApprovers": {
  "services": { "svc:slowshield": ["tag:slowshield"] }
},
"grants": [{
  "src": ["autogroup:member", "autogroup:tagged"],
  "dst": ["svc:slowshield"],
  "ip":  ["443"]
}]
```

### On a host

SlowShield itself listening on `127.0.0.1:8080`, without Caddy in front: Tailscale ends TLS. For example:

```sh
docker run -d --restart unless-stopped -p 127.0.0.1:8080:8080 -v slowshield:/data \
  -e SLOWSHIELD_PUBLIC_URL=https://slowshield.<your-tailnet>.ts.net ghcr.io/squirro/slowshield:<version>
```

Then:

```sh
sudo tailscale serve --service=svc:slowshield --https=443 http://127.0.0.1:8080
```

Tailscale ends TLS and forwards plain HTTP to SlowShield on the same host. The same configuration as a file, the
format `tailscale serve get-config --all` prints:

```json
{
  "version": "0.0.1",
  "services": {
    "svc:slowshield": {
      "endpoints": { "tcp:443": "http://127.0.0.1:8080" }
    }
  }
}
```

```sh
sudo tailscale serve set-config --all serve.json
sudo tailscale serve advertise svc:slowshield
```

Before upgrading or stopping a host, take it out of the Service; the other hosts take over:

```sh
sudo tailscale serve drain svc:slowshield
```

### From Kubernetes, with the Helm chart

Run a small Tailscale Deployment next to the release:
[`deploy/helm/slowshield/examples/tailscale-service.yaml`](../deploy/helm/slowshield/examples/tailscale-service.yaml).
It does what the hosts do (`serve set-config`, then `serve advertise`), with the official image pinned by digest,
non-root, in userspace mode, on a read-only root filesystem, and its identity in a Kubernetes Secret.

Why not the Tailscale Kubernetes operator: its ingress refuses a Tailscale Service it didn't create. A Service made in
the admin console, or shared with `tailscale serve` hosts, stops it with "does not contain owner annotation". If the
operator creates the Service instead, it owns it: deleting the Ingress deletes the Service for every host.

Three details make the Deployment work with the chart's Caddy:

- **HTTPS to Caddy, verified.** Caddy redirects plain HTTP to HTTPS, so a plain-HTTP backend loops. Caddy signs with
  its own root CA (`tls.mode: internal`): read it as the chart's NOTES show, put it in a ConfigMap, and add it to the
  system roots with `SSL_CERT_DIR=/etc/ssl/certs:/caddy-ca`, so tailscaled's own connections keep the usual ones. The
  backend is then plain `https://`. Don't use `https+insecure://`: a backend Tailscale doesn't verify could be
  impersonated from inside the cluster and serve forged packages.
- **The TLS name must be the Service name.** Caddy runs with `strict_sni_host`: the TLS name must equal the Host
  header, which is the Service name. A backend URL with the cluster name
  (`https://slowshield.slowshield.svc.cluster.local`) gets `421 Misdirected Request`. The backend URL uses
  the Service name instead, and the pod's `hostAliases` points that name at the chart Service's ClusterIP. Tailscale
  dials backends with the system resolver (`/etc/hosts`), not MagicDNS, so this doesn't loop back into the tailnet.
- **The chart's `hostnames` must include the Service name**, so Caddy serves it:
  [`examples/follower-values.yaml`](../deploy/helm/slowshield/examples/follower-values.yaml).

The auth key (single-use, pre-approved, tagged `tag:slowshield`) is needed only for the first start. After that the
node signs in from its state Secret; the example passes the key only when it is set, so its Secret can be deleted.

### Which instance a client reaches

This is a tailnet-wide setting (admin console: Settings → General → Route selection), and it also applies to subnet routers and app connectors:

| Route selection | A client reaches |
|---|---|
| Active-passive failover (the default) | one instance; another takes over if it goes away |
| Regional routing (Premium and Enterprise plans) | an instance in its DERP region |
| MagicRoute (beta) | its nearest healthy instance |

### Moving clients to the Service URL

Clients set up with an instance's own name keep using it. To move them without breaking them, set
[`setup_url`](configuration.md) (`SLOWSHIELD_SETUP_URL`) to the Service URL on that instance:

- its Setup page then gives new clients the Service URL, with a notice that the old name keeps working;
- it still answers under `public_url`, and the URLs it hands out (npm tarballs, Cargo downloads, the NuGet service
  index, Composer dists, shield wall invites) stay there.

Instances that clients only reach through the Service can use the Service URL as `public_url` directly.

## A follower whose leader is only on the tailnet

A leader can live on the tailnet only, for example `slowshield.example.com` as a CNAME to the leader host's MagicDNS
name. Followers then need a way to that host. They keep the leader's URL and certificate either way. With a publicly
trusted certificate on the leader, they need no CA (`leaderPubliclyTrusted`, `SLOWSHIELD_LEADER_CA_FILE` otherwise).

### A container on a tailnet host

The host reaches the leader over the tailnet, but a container with its own DNS (for example `--dns 9.9.9.9`) can't
resolve the MagicDNS name. Give the container the leader's tailnet address:

```sh
docker run ... --add-host "slowshield.example.com:$(tailscale ip -4 <leader-device-name>)" ghcr.io/squirro/slowshield:<version>
```

### A Kubernetes cluster with the Tailscale operator

Use an egress proxy:
[`examples/tailnet-leader-egress.yaml`](../deploy/helm/slowshield/examples/tailnet-leader-egress.yaml). It contains a
ProxyGroup of type `egress`, and an ExternalName Service annotated with `tailscale.com/tailnet-fqdn` and
`tailscale.com/proxy-group`.

- **Port 443 is kept.** The operator points the ExternalName Service at a ClusterIP Service in its namespace, which
  keeps port 443 (only the proxy pods' target port is allocated).
- **`hostAliases` maps the leader's name to it.** The chart's `hostAliases` points the leader's name at that ClusterIP,
  so the follower keeps the leader's URL and certificate.
- **The proxies' tag must reach the leader** on 443 in the tailnet policy.
- **With NetworkPolicy enforced,** `shieldwall.leaderEgress` must allow the proxy pods on any port, because the target
  port is allocated.

[`examples/follower-values.yaml`](../deploy/helm/slowshield/examples/follower-values.yaml) has the values for both
setups on this page. For installing and pairing, see the
[chart README](../deploy/helm/slowshield/README.md#a-shield-wall-follower).
