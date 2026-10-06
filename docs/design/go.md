# Go modules

Status: implemented (https://github.com/squirro/slowshield/issues/15, proposal in
[this comment](https://github.com/squirro/slowshield/issues/15#issuecomment-5990538536)).

SlowShield serves Go modules at `/go/` as a `GOPROXY`, with the same guarantees as PyPI and npm. Versions younger
than the delay are held back and known malware is refused. Every `.mod` and `.zip` is checked against the checksum
database and against the fingerprint recorded on its first download.

```bash
go env -w GOPROXY=https://slowshield.example.com/go
```

Don't add `,direct` or `|` to `GOPROXY`. With `,direct`, the go command fetches from the origin whenever the proxy
answers 404 or 410; with `|`, on any error. `GOSUMDB` stays at its default. SlowShield proxies `sum.golang.org`: it
answers `/go/sumdb/sum.golang.org/supported`, so the go command sends all its checksum-database traffic through
SlowShield and clients need no other route out. Private modules keep bypassing the proxy through `GOPRIVATE`.

## Endpoints

| Path under `/go/` | Behaviour |
|---|---|
| `<module>/@v/list` | Versions that are too new or blocked are left out. Header: `X-SlowShield-Held-Versions` |
| `<module>/@v/<version>.info` | Age-checked. Branch and commit queries are resolved by the mirror first; the resolved version is then checked |
| `<module>/@v/<version>.mod`, `.zip` | Age-checked, verified against the `h1:` hashes from `sum.golang.org` and the first-seen fingerprint, then cached |
| `<module>/@latest` | The newest allowed listed version. For modules without tags, the mirror's answer (the default branch's newest commit) if it is old enough, else the newest commit SlowShield knows to be old enough. The go command asks every module in a build for `@latest` to check for retractions |
| `sumdb/sum.golang.org/{supported,latest,lookup/…,tile/…}` | Passed through unchanged; lookups and tiles are cached |

Module paths and versions arrive case-encoded (`!a` for `A`); SlowShield stores them decoded, which is how OSV,
GitHub and pkg.go.dev name them. Everything outside the protocol is 404, so `/go/` is never an open proxy.

Refusals are `403` (too new, with `Retry-After`) and `451` (malware, tampering), never `404` or `410`. Even a client
configured with `,direct` therefore doesn't go around SlowShield. Bodies are `text/plain; charset=utf-8`, which the
go command prints under `server response:` (its first 8 lines):

```
go: example.com/hello@v1.2.0: reading https://slowshield.example.com/go/example.com/hello/@v/v1.2.0.info: 403 Forbidden
	server response:
	slowshield: example.com/hello@v1.2.0 is too new.
	It was published 2026-10-03T08:21:51Z (2.0 days ago); this proxy requires 7 days.
	It becomes available at 2026-10-10T08:21:51Z.
	Use an older version, or ask your SlowShield administrator for an exception.
```

## Publish time

The `Time` in `.info` is the commit time. The author sets it and can backdate it, so SlowShield never uses it. Three
server-side sources were checked on 2026-10-05:

- **index.golang.org** records when the mirror first cached a version. Rejected for two reasons:
  - **Load.** Each deployment would first download an 8-day window: about 400 requests and 94 MB, since the index
    doesn't compress. After that it would poll about 2,900 requests (12 MB) a day, whether or not anyone uses Go.
  - **Fails open.** Whenever that copy is incomplete (a fresh container, a laptop that was off), a new version
    looks old.
- **deps.dev `publishedAt`** is the commit time. Rejected.
- **The `Last-Modified` of `.mod` and `.zip` on proxy.golang.org** is the mirror's storage write time. Chosen.

| Version | Commit time | First cached (index.golang.org) | `Last-Modified` |
|---|---|---|---|
| yaoapp/registry v1.0.2 | 2026-03-03 | 2026-10-05 07:31:17.22 | 07:31:17 |
| ul-mds/gecko (pseudo-version) | 2025-01-30 | 2026-10-04 07:54:08.27 | 07:54:08 |
| ReF1nd/sing-box v1.6.6 | 2023-11-21 | 2026-10-05 06:54:08.41 | 06:54:08 |
| pkg/errors v0.8.0 | 2016-09-29 | – | 2019-04-11 (the mirror's launch) |

The rules:

1. **Publish time = `Last-Modified` of the `.mod`.** It is stored once per module version (in `package_versions`)
   and never changes, so a version that is old enough stays old enough. Without a plausible value (missing, before
   the mirror's launch in April 2019, or in the future), the version's clock starts when SlowShield first sees it.
   The mirror's `200` proves the version exists, so this can't age anything in advance.
2. **A version SlowShield hasn't seen** gets a `HEAD .mod` with `Disable-Module-Fetch: true`, so the mirror answers
   from its cache only.
   - A `200` carries the time.
   - A `404` means the mirror doesn't have the version yet. SlowShield fetches the `.mod` once, the mirror stores
     it, and its clock starts now.
   - If the version doesn't exist, the `404` is passed on and nothing is recorded. Nobody can age a version before
     it exists.
3. **`@v/list`** checks versions from the highest release down until the first one that is old enough, which is
   what `go get -u` picks.
   - Prereleases above that version are checked too, so `go list -m -versions` doesn't show them.
   - Lower versions are listed without a check: every `.info`, `.mod` and `.zip` request is checked anyway.
   - At most 20 unknown versions are looked up per evaluation.
4. **No time can be established** (the mirror is unreachable): that one version gets `503`. Versions decided
   earlier keep working.

`Last-Modified` isn't documented. A nightly check (`tests/e2e/test_live.py`) compares it with index.golang.org for
one recent version.

## Policy

- **Per version, like npm.** The same delay, exceptions (`ecosystem = "go"`; `version = "1.2.3"` and `"v1.2.3"`
  both match) and fail-open apply. A module none of whose versions is old enough yet is served anyway, and a
  `fail_open` event is recorded. For a module without tags, the versions are the pseudo-versions SlowShield has
  looked up.
- **Pins are refused, not downgraded.** Go builds the exact versions go.mod requires, so a requirement that is too
  new fails with `403`. Renovate `minimumReleaseAge` and Dependabot `cooldown` keep pins from getting ahead of the
  delay.
- **`enforce_age_on_download = false`** only filters lists; `.info`, `.mod` and `.zip` are served regardless of age.

## Integrity

| Check | Go |
|---|---|
| Registry digest | the `h1:` hashes from the `sum.golang.org` lookup: of the go.mod file, and of the files inside the zip (dirhash, computed on the spooled file before the final chunk is released) |
| Size | `Content-Length` |
| Trust on first use | sha256 of the bytes first served, per `/<module>/@v/<version>.{mod,zip}`. Module versions never change, so a mismatch is tampering |

- **The lookup costs nothing extra.** SlowShield's lookup is cached and answers the client's own lookup of the same
  version.
- **It also protects clients with `GOSUMDB=off`,** which corporate networks often set when `sum.golang.org` is
  unreachable.
- **Without the artifact cache** (`cache.artifacts_enabled = false`), the zip hash isn't checked server side. The
  go command still checks it.
- **`.info` and `@v/list` aren't signed.** They are cached as metadata, without a fingerprint.

The mirror redirects large zips to signed URLs on `storage.googleapis.com`. Redirects are followed only to the hosts
in `upstreams.go.download_hosts`.

## Upstream load

| | Requests |
|---|---|
| Startup, background | none |
| A new module version | the client's own requests, plus one `HEAD` |
| `go get -u` on a module | one `HEAD` per newly seen version, until one is old enough |

With two or more developers, SlowShield causes less load than going direct, because they share its cache.
`slowshield_publish_time_lookups_total{result}` counts the extra requests.

## Limitations and follow-ups

- The go command downloads toolchains (`golang.org/toolchain`) through `GOPROXY`, so new Go releases are held like
  any other module. An exception releases them early:

  ```toml
  [[exceptions]]
  ecosystem = "go"
  package = "golang.org/toolchain"
  delay_days = 0
  ```

- A retraction published in a held version stays invisible until that version is allowed.
- Follow-up: use the checksum database's record number as a second clock (a record near the end of the log is new).
  It isn't in the first version, because modules cached before the checksum database existed can get their record
  only now.
