# slowshield-website

The slowshield.net landing page: a static site baked into the SlowShield Caddy image (Amazon Linux 2023,
distroless, non-root, read-only). TLS is expected at your ingress (e.g. cert-manager); the pod serves HTTP on 8080.
All hosts other than `canonicalHost` are redirected (308) to it.

```bash
helm install website deploy/helm/slowshield-website \
  --set ingress.className=nginx \
  --set ingress.annotations."cert-manager\.io/cluster-issuer"=letsencrypt
```

| Value | Default | |
|---|---|---|
| `canonicalHost` | `slowshield.net` | redirect target for the other domains |
| `ingress.hosts` | the three domains + `www.` | |
| `image.digest` | — | pin by digest in production |
| `networkPolicy.ingressNamespaceSelector` | `ingress-nginx` namespace | where your ingress controller runs |

Build locally: `docker buildx build -f containers/website/Dockerfile --build-arg CADDY_IMAGE=slowshield-caddy:dev -t slowshield-website:dev --load .`
