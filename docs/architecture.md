# Architecture

```
          ┌──────────── Caddy (TLS 1.3, H1/H2/H3, HSTS) ────────────┐
client ──▶│  reverse_proxy → slowshield:8080 (X-Forwarded-*)       │
          └──────────────────────────────────────────────────────────┘
                                   │
   Granian (Rust HTTP server, ASGI, uvloop) — N workers (processes; threads on free-threaded 3.15t)
                                   │
   SlowShield ASGI app  (src/slowshield/app.py)
   ├── tracing + security headers middleware
   ├── host router ── PyPI service  (ecosystems/pypi)  ─┐
   │               ├─ npm service   (ecosystems/npm)   ─┤── policy (policy.py) ── blocklist (blocklist.py)
   │               ├─ Go service    (ecosystems/go)    ─┤                      └─ config exceptions
   │               ├─ Maven service (ecosystems/maven) ─┤
   │               └─ UI            (ui/)               │
   ├── metadata LRU (cache/metadata.py, bytes-weighted, single-flight, ETag revalidation)
   ├── artifact server (ecosystems/artifacts.py) ── on-disk verified cache (cache/artifacts.py)
   ├── upstream client (upstream.py: pyreqwest, HTTP/2, no open redirects, size caps)
   ├── recorder (stats/events aggregated in memory, flushed every 5 s)
   ├── SQLite (db/): WAL, one batched writer thread, per-thread read-only connections
   └── leader (flock on /data/leader.lock): feeds, cache eviction/scrub, retention
```

## Request flow: PyPI

1. `GET /simple/<name>/` → name validated and PEP 503-normalised (non-canonical names redirect).
2. Package-level blocklist hit → `451`.
3. Project document from this worker's memory, from the metadata cache shared by all workers
   (`metadata-cache.db`), or `GET <mirror>/simple/<name>/` with
   `Accept: application/vnd.pypi.simple.v1+json` (revalidated with `If-None-Match` after the TTL; a stale
   copy is served if upstream is down).
4. Policy per **file**: blocked versions removed, files younger than the delay held back; if nothing is
   old enough, fail open over the non-blocked files. The evaluation is cached until the next file
   "graduates" or the policy/blocklist generation changes.
5. Rendered as PEP 691 JSON or HTML depending on `Accept`, with relative file URLs.

`GET /packages/<aa>/<bb>/<hash>/<file>` → strict path check → file must be listed in the current
project document (so lockfiles cannot bypass policy) → blocklist → age gate (403 + `Retry-After`) →
cache hit (zero-copy, Range) or verified stream from `files.pythonhosted.org`.

## Request flow: npm

The packument is decoded lazily with msgspec: only the top-level map, `time`, `dist-tags` and the
`versions` map (as raw JSON blobs) are parsed. Kept versions are spliced back byte-for-byte after a
tarball URL rewrite, so every field, signature and attestation survives. `latest` is recomputed as
the highest allowed stable version; other tags whose target is filtered disappear. Abbreviated
(corgi) documents are produced for clients that ask for them.

## Request flow: Go

`/go/` speaks the GOPROXY protocol ([design/go.md](design/go.md)). Paths are validated and the `!` case-encoding
decoded; anything outside the protocol is 404.

1. Package-level blocklist hit → `451` (text/plain, which the go command prints).
2. Publish time of the version: `package_versions` (known from earlier), else a `HEAD .mod` with
   `Disable-Module-Fetch: true` to the mirror, whose `Last-Modified` is when the mirror first stored the version. A
   version the mirror doesn't have yet is fetched once; its clock starts then.
3. `@v/list`: versions are checked newest first until one is old enough; too-new and blocked ones are left out.
   `.info`, `.mod`, `.zip`: version block → `451`, too new → `403` + `Retry-After`, unless the module fails open.
4. `.mod` and `.zip` go through the artifact server, checked against the `h1:` hashes from the cached
   `sum.golang.org` lookup. `/go/sumdb/sum.golang.org/…` is passed through unchanged.

## Request flow: Maven

`/maven/<repo-id>/` serves the standard Maven layout ([design/maven.md](design/maven.md)); `/maven/all/` sends
Google Maven's groups to Google and the rest to Central. Paths outside the layout are 404.

1. Blocklist hit → `451`.
2. `maven-metadata.xml`: versions are checked newest first (Maven's version order) with a `HEAD` of each unseen
   version's `.pom` until one is old enough; too-new and blocked versions are left out, `<latest>`/`<release>`
   recomputed, the checksum files computed from the filtered body.
3. A file: a version known to be too new → `425` without an upstream request; otherwise the file's own
   `Last-Modified` (or the version's first-listed time, if earlier) decides when the upstream response arrives.
   The download is checked against the repository's checksum and the first-seen fingerprint.

## Integrity

Artifacts are streamed to the client while sha256 (always), blake2b-256 (PyPI path), sha512 / sha1
(npm `dist.integrity` / `shasum`) are computed and the bytes are teed to `/data/cache/tmp`. A Go zip's `h1:` covers
the files inside it, so it is computed from the temp file once the body is complete. The last
chunk is withheld until all digests match the registry's published values and the first-seen
fingerprint; on a mismatch the response is aborted and the event recorded. Verified bodies are
fsync'ed and renamed into the content-addressed cache.

## Storage

One SQLite file (`/data/slowshield.db`), schema in `db/migrations/`. Writes go through a single thread
that batches operations into transactions; request handlers never wait on writes except for the
trust-on-first-use insert. Stats are rolled up hourly and daily; events, stats and client IPs have
retention limits.

## Multi-worker behaviour

Each Granian worker has its own caches and writer. SQLite WAL with `busy_timeout` serialises writes
across processes; exactly one worker holds the leader lock and runs feeds and maintenance, and others
pick up blocklist changes via a generation counter. On free-threaded Python, workers are threads in
one process sharing a single interpreter.
