# Integrity & tamper detection

Every artifact (wheel, sdist, PEP 658 `.metadata`, npm tarball, Go `.mod` and `.zip`, Maven file, `.crate`, container
image manifest and blob) is checked on the way through:

| Check | PyPI | npm | Go | Maven | Cargo |
|---|---|---|---|---|---|
| Registry digest | `hashes.sha256` from the PEP 691 index (and `core-metadata` sha256 for `.metadata`) | `dist.integrity` (sha512); `dist.shasum` (sha1) for old versions without integrity | `h1:` from the `sum.golang.org` lookup: of the go.mod, and of the files inside the zip (computed on the spooled file before the final chunk is released) | Central's `x-checksum-sha1` header; the `.sha1` file (Google, operator repositories); the sha256 in the Plugin Portal's redirect path | the index line's `cksum` (sha256) |
| Path digest | the `/packages/aa/bb/<60 hex>/` path is the file's blake2b-256 | — | — | — | — |
| Size | `size` from the index | `Content-Length` | `Content-Length` | `Content-Length` | `Content-Length` |
| Trust on first use | sha256 of the bytes first served, stored per artifact path | same | same | same | same |

The Go checksum lookup is cached and answers the go command's own lookup of the same version, so it costs no
extra request. It also protects clients that set `GOSUMDB=off`.

## Streaming without trusting the stream

On a cache miss the body is streamed to the client while all digests are computed and the bytes are
written to a temporary file. **The final chunk is held back until every check has passed.** On a mismatch
the response is aborted (the client sees a truncated body against the announced `Content-Length` and the
install fails), the temp file is discarded and an event is recorded:

* `integrity_mismatch` — the bytes don't match the registry's own digest (CDN corruption, MITM, or a
  registry inconsistency); later requests retry upstream.
* `tampered` — the bytes differ from the fingerprint recorded the first time this artifact was served.
  Filenames on PyPI, `name@version` on npm and crates.io, and module versions in Go are immutable, so this is
  definitive: the
  artifact is marked and every later request gets `451 tamper_detected` until an operator investigates.

Upstream error responses (non-2xx) are never hashed.

## Container images

Image content is addressed by digest, so the digest is the check ([design/oci.md](design/oci.md)):

* **Manifests** must hash to the requested digest, or to `Docker-Content-Digest` for a tag, and are kept by digest.
  A mismatch is never served.
* **Blobs** are checked against their digest while streaming, with the last chunk held back, like every artifact. A
  mismatch is a `tampered` event and a `403`.
* **Redirects** to a CDN are followed only to the registry's `download_hosts`, and the registry token is never sent
  there.
* **Takedowns.** A cached manifest is re-checked upstream at most every 5 minutes while it is pulled; one the
  registry removed is refused from then on.

## Verified cache

Verified bodies are fsync'ed and atomically renamed into `/data/cache/objects/<aa>/<bb>/<sha256>`, then
recorded in the database. Cache hits are served zero-copy by Granian (`pathsend`), support `Range`, and are
re-hashed periodically by a scrub job (`cache.scrub_interval_hours`); corrupted objects are removed. The
cache is capped (`cache.artifacts_max_gb`) with least-recently-used eviction; evicted files go through a
`trash/` grace period so in-flight downloads complete.

## Responding to a tamper event

1. Check `/ui/security?type=tampered` (stored vs observed digests, client IPs).
2. Compare with the registry's published digest and the project's release notes / advisories.
3. If the change is legitimate (extremely rare), clear the flag for that path:
   `UPDATE artifacts SET tampered = 0, sha256 = NULL WHERE path = '<path>';`
   The next download records a new fingerprint.
