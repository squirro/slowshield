# Container images (OCI)

Status: implemented (https://github.com/squirro/slowshield/issues/22). Registry behaviour was checked with live pulls
through all seven built-in registries on 2026-10-06. Client behaviour was checked on 2026-10-07 with real clients
against the e2e stack: containerd 2.2.7 (ctr, nerdctl 2.3.5), Docker 29.8.2 on both image stores, Podman 5.8.7,
BuildKit 0.33.1, skopeo 1.22.3 and crane. `tests/e2e/test_containers.py` repeats those checks on every pull request.

SlowShield serves container images through the OCI distribution API at `/v2/`. Tags lag behind: a tag resolves to the
newest digest it has pointed to for at least the delay, so `FROM nginx:latest` keeps working, about a week behind. A
digest pin that is too new, and a blocked image, are refused with a message most clients print. Manifests are checked
against their digests and cached; layers are checked while they stream, and aren't stored unless the layer store is
on.

## Client setup

The Setup page has every file below with the instance's host filled in.

| Client | Setup | Covers | Goes around a refusal? |
|---|---|---|---|
| containerd 2.x (Kubernetes, nerdctl) | `/etc/containerd/certs.d/_default/hosts.toml`, below | every registry | no |
| Docker 29 on the containerd image store | the same file in `/etc/docker/certs.d/_default/` | every registry, `docker pull` and `docker build` | no |
| Docker on the classic image store | `daemon.json` `"registry-mirrors": ["https://HOST"]` | Docker Hub only | **yes**: Docker pulls from Docker Hub itself |
| Podman, CRI-O, Buildah, skopeo | `/etc/containers/registries.conf.d/50-slowshield.conf`: `prefix = "docker.io"`, `location = "HOST/docker.io"`, one entry per registry | the registries listed | no |
| BuildKit (also `docker buildx` builders with their own BuildKit) | `buildkitd.toml`: `[registry."docker.io"] mirrors = ["HOST"]` | the registries listed | **yes**: BuildKit pulls from the registry itself |
| crane, skopeo, kaniko, a Dockerfile | the host in front of the name: `HOST/docker.io/library/nginx:1.29` | that image | no |

```toml
# /etc/containerd/certs.d/_default/hosts.toml (and /etc/docker/certs.d/_default/hosts.toml)
server = "https://slowshield.example.com"
capabilities = ["pull", "resolve"]
```

- **`server`, not a `[host]` entry.** containerd tries the next host after any `4xx` or `5xx`, and the last host is
  the `server`. With SlowShield as a `[host]` and no `server`, a refused pull went on to registry-1.docker.io.
- **Pushes.** The file above is pull-only, so a push fails with "no push hosts". A registry you push to gets its own
  file, which keeps pulls on SlowShield and sends pushes to the registry:

  ```toml
  # /etc/containerd/certs.d/ghcr.io/hosts.toml
  server = "https://ghcr.io"
  capabilities = ["push"]

  [host."https://slowshield.example.com"]
    capabilities = ["pull", "resolve"]
  ```

  The root `capabilities = ["push"]` only takes effect together with `server`: in `_default` without one, a refused
  pull went to the registry again.
- **Kubernetes.** The kubelet pulls through containerd's CRI plugin, which reads the files only when its
  `config_path` names the directory: `[plugins.'io.containerd.cri.v1.images'.registry] config_path =
  "/etc/containerd/certs.d"` (containerd 2.x; `[plugins."io.containerd.grpc.v1.cri".registry]` in 1.7). The default
  is empty. Check with `containerd config dump | grep config_path`.
- **Docker's image store.** `docker info` lists `io.containerd.snapshotter.v1` under Storage Driver on the
  containerd store, the default for new installs since Docker 29. Docker 29.8 reads `/etc/docker/certs.d` for both
  `docker pull` and `docker build`.
- **BuildKit mirrors without a path.** containerd's resolver, which BuildKit uses, names the registry in `?ns=`. A
  mirror written with a path (`HOST/docker.io`) needs its `http` or `ca` settings under that exact name, and when they
  were missing BuildKit went to the registries directly.
- **Clients that go around a refusal** (BuildKit, Docker's classic store) are bound only by an egress firewall that
  blocks the registry hosts.

## What clients see

| Request | Behaviour |
|---|---|
| `GET /v2/` | `200`, without an auth challenge: SlowShield authenticates upstream |
| manifest by tag | resolved upstream with `HEAD`, kept for 5 minutes. Serves the newest old-enough, unblocked digest of the tag; `X-SlowShield-Held-Versions` says how many newer ones are held. Nothing old enough: `403` |
| manifest by digest | served if old enough, else `403`: pins are refused, not downgraded |
| blob | streamed by digest and checked while streaming; the last chunk is held back until it matches |
| `tags/list`, referrers (cosign `.sig`/`.att` tags included) | passed through; `Link` headers point back at SlowShield |
| push methods, `_catalog`, anything else | `405` or `404` with an OCI error body |

Paths follow Docker's reference rule: a first segment with a `.` or `:`, or `localhost`, is a registry host.
`/v2/ghcr.io/squirro/slowshield/…` goes to ghcr.io if it is configured, any other host gets `403`, so this is never an
open proxy. `/v2/library/nginx/…` goes to Docker Hub, or to the registry containerd names in `?ns=`.

**Every refusal is `403` with an OCI error body**: too new, blocked, taken down and tampered alike, with `Retry-After`
and `X-SlowShield-Reason` (`too_new`, `blocked`, `taken_down`, `tampered`, `registry_not_configured`).

```json
{"errors":[{"code":"DENIED","message":"slowshield: docker.io/library/brandnew:latest (sha256:162a60de2ed8…) is too new. It was pushed 2026-10-06T21:06:02Z (1.0 hours ago); this proxy requires 7 days. It becomes available at 2026-10-13T21:06:02Z. Use an older tag or digest, or ask your SlowShield administrator for an exception."}]}
```

What the clients printed:

| Client | Output |
|---|---|
| Docker 29.8 (containerd store) | `Error response from daemon: error from registry: slowshield: … is too new …` |
| `docker build`, BuildKit 0.33 | `… 403 Forbidden` and on the next line `denied: slowshield: … is too new …` |
| Podman 5.8, skopeo 1.22 | `reading manifest latest in HOST/docker.io/library/brandnew: denied: slowshield: …` |
| crane | `DENIED: slowshield: …` |
| containerd 2.2 (ctr, nerdctl 2.3, Kubernetes events) | `unexpected status from HEAD request to …: 403 Forbidden`, without the message |

**Why `403`, even for malware** (the other ecosystems use `451`): containerd resolves with `HEAD`, and newer versions
repeat a `403`, and only a `403`, as `GET` to show the body. **Never `404`:** containerd would try the next host, and
Docker's classic store would go to Docker Hub. Upstream failures are `503` with `Retry-After`.

## Publish time: tags are the hard part

An image config's `created` field is set by whoever builds the image (`gcr.io/distroless/static` says 1970-01-01), so
it is never used. No registry sends `Last-Modified` on manifests. What registries expose:

| Registry | When a tag got its digest | Tag history | Source (`times`) |
|---|---|---|---|
| Docker Hub | Hub API `tag_last_pushed`, current digest only (not counted as a pull) | none | `hub` |
| Quay | `start_ts`/`end_ts` per tag and digest | complete | `quay` |
| registry.k8s.io, gcr.io | `timeUploadedMs` per digest in `tags/list` | per digest | `gcr` |
| MCR | `lastModifiedDate` per tag | none | `mcr` |
| GHCR, ECR Public | nothing anonymous | none | `none` |

1. **The unit is the tag's target**, usually an index; its platform and attestation manifests come with it.
2. **Two clocks per tag → digest:** the registry's time, where it has one, and when SlowShield first saw the tag point
   there. The earlier one counts, as for Maven. A publisher can push by digest long before tagging, so a manifest's
   storage time is never used for tags. A failed lookup of the registry's time is retried after 10 minutes.
3. **Time travel.** A tag resolves to the newest digest it pointed to that is old enough, not blocked and not taken
   down. The history comes from SlowShield's own observations and from registries that keep one (Quay, Artifact
   Registry). The package page shows it per tag.
4. **Digest pins** take the earliest time any tag pointed to them or to their index; without any, the registry's
   storage time; and first sight in any case.
5. **Nothing old enough:** `403`. Exception: during an instance's first `default_delay_days`, a tag it has no history
   for is served at its current digest and recorded as fail-open, so a new instance doesn't refuse half of Docker Hub
   (on 2026-10-06, 11 of 15 popular Docker Hub tags had been pushed within the last 7 days). With
   `upstreams.oci.fail_open = false` it is strict from day one.
6. **Takedowns.** A cached manifest is re-checked with a `HEAD` (not counted as a Docker Hub pull) at most every
   5 minutes while it is being pulled. If the registry dropped it, as Docker Hub did with the malicious Trivy images,
   SlowShield refuses it too, and time travel skips it.

**Why it's worth it:** Trivy's Docker Hub tags `0.69.4` and `latest` were malicious from 2026-03-19 18:24 to
03-23 01:36 UTC. With a 7-day delay, `latest` would have stayed on 0.69.3.

## Policy

- **Names.** The ecosystem is `oci`, the package is the canonical repository (`docker.io/library/nginx`), and the
  version is a digest or a tag. `nginx`, `index.docker.io/nginx` and `docker.io/library/nginx` are one repository.
- **Delay and exceptions:** the usual ones (`ecosystem = "oci"`). An exception for a digest wins over one for a tag,
  which wins over one for the repository. Prefer digests: a tag exception follows the tag wherever it moves.
- **Blocks.** No malware feed covers images: OSV and GitHub have no container ecosystem. Operators block a repository,
  tag or digest with `[[blocks]]` in config.toml (any ecosystem, see configuration.md). A blocked tag is refused; a
  blocked digest is skipped by time travel and refused when pinned.
- **No image scanning.** The delay, operator blocks and registry takedowns are the protection.

## Integrity

| Check | |
|---|---|
| Manifests | the sha256 of the body must equal the requested digest, or `Docker-Content-Digest` for a tag; at most 4 MB |
| Blobs | the digest is the sha256 of the content: checked while streaming, the last chunk held back until it matches |
| Tag moves | every digest a tag pointed to is kept, with both clocks |
| Redirects | blob redirects are followed only to the registry's `download_hosts`; `Authorization` and cookies are never sent to another host |

- **Tokens** are fetched per registry and repository (`repository:<path>:pull`), with Basic credentials when
  `token_file` is set, and kept until 30 seconds before they expire.
- **cosign and notation signatures** pass through as referrers and tags; verifying them is a possible later,
  opt-in feature.

## Caching

- **Manifests** (a few KB) are kept in the metadata store by digest for 30 days. Tag resolutions are kept for
  5 minutes, shared by all workers.
- **Image configs** go into the artifact cache like package files.
- **Layers are not stored by default.** They are streamed and checked. One platform of nginx is 64 MB and ML images
  are gigabytes, so storing them would evict the PyPI and npm files the cache is there for. Not storing them costs
  bandwidth, not Docker Hub pulls.
- **The layer store.** `upstreams.oci.layer_cache_gb` above 0 keeps layers in a separate LRU store under
  `<data_dir>/cache/oci-layers` with its own budget, so it can sit on a disposable volume. For CI fleets, 50 to 100 GB
  is a reasonable start. Its size is the `oci_layers` cache in the metrics.

## Docker Hub's rate limit

- **What counts.** Only a manifest `GET` counts as a pull; `HEAD` and blob downloads don't. Anonymous pulls are
  limited per IP (`ratelimit-limit: 100;w=3600` on 2026-10-06).
- **SlowShield's usage.** It resolves tags with `HEAD` and fetches each manifest once for all clients: at most one pull
  per new digest, not one per machine.
- **Shared IPs.** `username` and `token_file` on the `docker.io` registry use a Docker Hub "Public Repo Read-only"
  access token, so pulls count against that account. `slowshield_oci_ratelimit_remaining` is what the registry last
  said was left.

## SlowShield's own images

Once an instance is healthy, its hosts can pull SlowShield's images through it, so new releases wait like everything
else. A Podman drop-in that names only the `ghcr.io/squirro` namespace:

```toml
# /etc/containers/registries.conf.d/50-slowshield-self.conf
[[registry]]
prefix = "ghcr.io/squirro"
location = "slowshield.example.com/ghcr.io/squirro"
```

- **Bootstrap.** The first start pulls from ghcr.io directly: SlowShield can't serve its own image before it runs.
- **No fallback.** Podman doesn't go around a refusal, which matters because `podman auto-update` restarts one unit at
  a time: with a fallback, the Caddy image check would go straight to ghcr.io while the app restarts.
- **The delay applies.** `:latest` moves 7 days after SlowShield first saw the new digest (GHCR has no times). An
  urgent fix gets a digest exception; release notes list the index digests.
- **Recovery.** If SlowShield can't start and its images are gone, remove the drop-in.
- **Kubernetes.** The Helm chart pins SlowShield's image by digest; a node that pulls through SlowShield needs the
  same bootstrap order.

## Configuration

```toml
[upstreams.oci]
enabled = true          # SLOWSHIELD_OCI_ENABLED, Helm ecosystems.oci.enabled
fail_open = true        # unset: the top-level fail_open. Only ever during the instance's first delay days
layer_cache_gb = 0      # Helm ecosystems.oci.layerCacheGb

# More registries, or changes to the built-in ones, keyed by the name clients use in image references.
[upstreams.oci.registries."registry.example.com"]
url = "https://registry.example.com"
download_hosts = ["cdn.example.com", "*.blob.example.net"]  # where blobs may redirect; `*` allowed
times = "none"          # hub, quay, gcr, mcr or none (first sight only)
times_url = ""          # required for hub (https://hub.docker.com), quay and mcr
aliases = []            # other names for it (index.docker.io)
enabled = true
username = ""           # with token_file: Basic credentials for the token service
token_file = ""
```

Built in: docker.io, ghcr.io, quay.io, registry.k8s.io, gcr.io, mcr.microsoft.com and public.ecr.aws, with their CDN
hosts and time sources. A table for one of them changes only the keys it sets: `enabled = false` switches it off,
`username` and `token_file` under `docker.io` add a Docker Hub token. Registries and `layer_cache_gb` decide which hosts SlowShield may reach
and what it stores, so changing them needs a restart.

## Upstream load

| | Requests |
|---|---|
| A tag | one `HEAD` per 5 minutes while it is pulled, shared by all clients and workers |
| Registry times | one request per tag (Docker Hub, Quay, MCR) or per repository (`tags/list` on Artifact Registry), cached for an hour |
| A manifest | one `GET` per digest, then a `HEAD` at most every 5 minutes while it is pulled (takedowns) |
| A config | one `GET`, then the artifact cache |
| A layer | one `GET` per pull, or the first time only with the layer store |
| Tokens | one per registry and repository until it expires |

## Limitations

- **Some clients go around a refusal.** Docker's classic image store and BuildKit pull from the registry after a
  refusal; only an egress firewall on the registry hosts closes that.
- **containerd 2.2 and older** show only `403 Forbidden`.
- **New instances** serve tags they have no history for during their first delay days (rule 5).
- **GHCR and ECR Public** times are SlowShield's own first sight.
- **Private images** and registries that need per-user credentials aren't supported.
- **Follow-ups:** redirecting blobs instead of streaming them, one upstream stream for concurrent misses of the same
  layer, cosign/notation verification, a namespace allowlist against typosquats, private registries.

## Code and tests

- `src/slowshield/ecosystems/oci/reference.py`: paths, Docker's reference rule, `?ns=`.
- `src/slowshield/ecosystems/oci/registry.py`: tokens, manifests with digest checks, rate-limit headers.
- `src/slowshield/ecosystems/oci/times.py`: the Docker Hub, Quay, Artifact Registry and MCR time sources.
- `src/slowshield/ecosystems/oci/service.py`: tag history, time travel, digest judgement, refusals, blobs, listings.
- `src/slowshield/ui/snippets.py` (`oci_tools`): the Setup page entries.
- `tests/unit/test_oci.py`, `tests/integration/test_oci.py` (fake registries and time APIs in `fakeupstream/`),
  `tests/e2e/test_containers.py` (real clients configured with the Setup page's files).
