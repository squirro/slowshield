# Integrity & tamper detection

Every artifact (wheel, sdist, PEP 658 `.metadata`, npm tarball) is checked on the way through:

| Check | PyPI | npm |
|---|---|---|
| Registry digest | `hashes.sha256` from the PEP 691 index (and `core-metadata` sha256 for `.metadata`) | `dist.integrity` (sha512); `dist.shasum` (sha1) for old versions without integrity |
| Path digest | the `/packages/aa/bb/<60 hex>/` path is the file's blake2b-256 | — |
| Size | `size` from the index | `Content-Length` |
| Trust on first use | sha256 of the bytes first served, stored per artifact path | same |

## Streaming without trusting the stream

On a cache miss the body is streamed to the client while all digests are computed and the bytes are
written to a temporary file. **The final chunk is held back until every check has passed.** On a mismatch
the response is aborted (the client sees a truncated body against the announced `Content-Length` and the
install fails), the temp file is discarded and an event is recorded:

* `integrity_mismatch` — the bytes don't match the registry's own digest (CDN corruption, MITM, or a
  registry inconsistency); later requests retry upstream.
* `tampered` — the bytes differ from the fingerprint recorded the first time this artifact was served.
  Filenames on PyPI and `name@version` on npm are immutable, so this is definitive: the artifact is marked
  and every later request gets `451 tamper_detected` until an operator investigates.

Upstream error responses (non-2xx) are never hashed.

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
