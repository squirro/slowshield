# Cargo and Rust

Status: implemented (https://github.com/squirro/slowshield/issues/16). It was checked on 2026-10-06 with real cargo
1.70, 1.80 and 1.99 against crates.io: resolution skipped a 3-day-old tokio release, Cargo.lock kept crates.io as
its source, every download was verified against the index, and a lockfile pinning the new release got the `403` text
below. The end-to-end tests run cargo 1.99 against the fake registry on every pull request.

SlowShield serves crates.io at `/cargo/` as a sparse registry that replaces `crates-io` in Cargo's configuration.
Versions younger than the delay are held back, known malware is refused, and every `.crate` is checked against the
index's `cksum` and the fingerprint recorded on its first download.

## Client setup

```toml
# $CARGO_HOME/config.toml (~/.cargo/config.toml)
[source.crates-io]
replace-with = "slowshield"

[registries.slowshield]
index = "sparse+https://slowshield.example.com/cargo/"
```

- **Lockfiles don't change.** Cargo.lock keeps `source = "registry+https://github.com/rust-lang/crates.io-index"`
  and crates.io's checksums, so a project builds the same with or without SlowShield.
- **`[registries.slowshield]`, not `[source.slowshield] registry = …`.** With the `[source]` form, `cargo info`
  refuses to run.
- **It has to be a file.** Source replacement can't be set through environment variables, so Cargo isn't part of the
  shell setup on the Setup page. Its Per tool entry has the file and a one-line command for CI and Dockerfiles.
- **Docker images.** The official `rust` images set `CARGO_HOME=/usr/local/cargo`, where `~/.cargo/config.toml`
  isn't read. The command writes `${CARGO_HOME:-$HOME/.cargo}/config.toml`.
- **Plain HTTP.** `sparse+http://localhost/cargo/` works with local HTTP.
- **Cargo 1.68 or later** (the sparse protocol).

## What clients see

| Path under `/cargo/` | Behaviour |
|---|---|
| `config.json` | `{"dl": "<public_url>/cargo/crates"}` (or the local HTTP origin). No `api`, so commands that need the crates.io web API stop instead of coming here |
| `<prefix>/<name>` (an index file) | Upstream lines byte for byte, except that a version too new or blocked gets `"yanked":true`. `ETag` of the served body, `304` on `If-None-Match`, `X-SlowShield-Held-Versions`. `451` when the crate is blocked as a whole |
| `crates/<name>/<version>/download` | `403` with `Retry-After` when too new, `451` when blocked or tampered, else verified, streamed and cached |
| anything else | `404` |

Index paths are the lower-case ones cargo asks for (`1/a`, `2/ab`, `3/a/abc`, `ab/cd/abcd…`); any other spelling is
a `404`.

Cargo prints the body of a failed download, so refusals are plain text:

```
error: failed to download from `https://slowshield.example.com/cargo/crates/tokio/1.53.2/download`

Caused by:
  failed to get successful HTTP response from `…/cargo/crates/tokio/1.53.2/download`, got 403
  body:
  slowshield: tokio@1.53.2 is too new.
  It was published 2026-10-03T11:18:32Z (3.0 days ago); this proxy requires 7 days.
  It becomes available at 2026-10-10T11:18:32Z.
  Use an older version (cargo update -p tokio@1.53.2 --precise 1.53.1), or ask your SlowShield administrator for an exception.
```

The suggested version is the newest one below the refused one that SlowShield would serve now.

How cargo treats statuses:

- **Downloads, 403 and 451:** the body is shown, nothing is retried or cached, and the next build asks again.
- **Downloads, 429 and 5xx:** retried. Upstream failures are `503` with `Retry-After: 10`, never `404`.
- **Index files:** `404` reads as "no matching package". For a crate blocked as a whole, cargo 1.99 shows the `451`
  body; 1.80 and older say "no matching package", which still stops the build.

## Held versions are marked yanked, not removed

| | Line removed | Line marked `"yanked":true` |
|---|---|---|
| New resolution (`add`, `update`, `generate-lockfile`, `install`) | newest remaining version | newest non-yanked version: the same |
| A committed Cargo.lock that pins a held version | resolver error ("failed to select a version …") | cargo asks for the download and prints the `403` above |
| A requirement only held versions satisfy | "candidate versions found which didn't match" | "version … is yanked" |

- **How.** A byte replacement of `"yanked":false`, the token crates.io writes on every line. A line without it, or
  that doesn't read back as yanked, is left out instead. Everything else, `pubtime` and `cksum` included, passes
  through unchanged.
- **When the hold ends**, the file and its ETag change, and `cargo update` picks the version up.
- **Lockfile pins are stopped by the download check.** With a warm index, a build only asks for the `.crate` files
  it is missing.
- **Versions yanked upstream** stay yanked and still download: cargo uses them only for an existing lockfile.

## Publish time

Every index line carries `pubtime`, which crates.io sets when the version is published (the author can't), and which
doesn't change when a version is yanked.

1. **Publish time = `pubtime`** from the index file SlowShield fetches anyway. No extra request, and no crates.io API.
2. **It never moves earlier.** The first `pubtime` seen for a version is kept in `package_versions`. If the index later
   states a different one, the later of the two counts.
3. **Without a plausible `pubtime`** (missing, without a time zone, before 2014 or in the future), the clock starts
   when SlowShield first sees the version listed (`first_listed`, as for Maven), and a warning is logged.
4. **Judged per version**, like npm: no requests per version, so no probe limit.

## Policy

- **Delay and exceptions:** the usual ones (`ecosystem = "cargo"`). Names are matched in crates.io's canonical form
  (lower case, `-` written as `_`), so `Fake-Hello` in an exception or an advisory names `fake_hello`. The UI shows
  that form.
- **No fail-open by default** (`upstreams.cargo.fail_open = false`), like Maven: nearly all RustSec malware
  advisories cover whole crates, typosquats and impersonations, which are brand new when they strike.
- **A pin that is too new is refused, not downgraded.**

## Integrity

| Check | |
|---|---|
| Registry digest | the index line's `cksum` (sha256 of the `.crate`), checked while streaming |
| Size | `Content-Length` |
| Trust on first use | the sha256 of the bytes first served, per crate version |

- **The download must match a line in the crate's current index file**, or it is a `404`.
- **The exact name upstream.** static.crates.io is sensitive to case and to `-` versus `_`, so SlowShield always
  asks for the index line's own spelling.
- **No redirects.** static.crates.io serves files directly; `download_hosts` is for mirrors that redirect.
- **Missing files.** static.crates.io answers `403` for a file it doesn't have. For a version the index lists, that is
  an upstream error: `503`.

## Malware feeds

- **OSV `crates.io` (`MAL-*`) and GitHub (`rust`)**, as for every ecosystem.
- **RustSec.** OSV's `crates.io` data includes the RustSec advisory database. Advisories categorised `malicious` are
  taken in, unless one of their aliases is a `MAL-*` id (that advisory covers it already). Most RustSec malware
  advisories have no `MAL-*` counterpart: on 2026-10-06, 70 blocks came from RustSec and 22 from `MAL-*`.
  - `introduced: "0.0.0-0"` with no end becomes a block of the whole crate.
  - A range with an end becomes a version range. RustSec writes exact versions as `>= 1.4.1, < 1.4.2-0`.
  - An open range from a real version on ("malicious from 2.0.0") is skipped: the versions crates.io accepted after
    removing the bad ones are not malware. The `MAL-*` and GitHub advisories cover those cases.
  - An advisory that loses the category lifts its blocks.
- **Why the blocklist matters here.** crates.io deletes malicious crates, often within hours. The blocklist covers
  those hours, keeps a deleted name blocked if it is registered again, and turns a lockfile that still names it into
  a `451` and a security event instead of a `404`.

## Configuration

```toml
[upstreams.cargo]
enabled = true                                    # SLOWSHIELD_CARGO_ENABLED, Helm ecosystems.cargo.enabled
fail_open = false
index_url = "https://index.crates.io"
download_url = "https://static.crates.io/crates"  # <download_url>/<name>/<version>/download
download_hosts = []
```

`index_url`, `download_url` and `download_hosts` decide which hosts SlowShield may reach, so changing them needs a
restart.

## Upstream load

| | Requests |
|---|---|
| Startup, background | none (the OSV feed already downloads `crates.io/all.zip`) |
| A crate's index file | one GET per metadata TTL, then `If-None-Match` (a `304` when unchanged), shared by all clients and workers |
| Publish times | none |
| A `.crate` | one GET, the first time; then the verified cache |
| crates.io API | none |

crates.io's data-access policy sets no rate limit for index.crates.io or static.crates.io; its 1 request per second
applies to the API, which SlowShield doesn't use.

## Limitations

- **Commands that need the crates.io web API.** `cargo search` fails ("registry does not support API commands");
  `cargo info` needs `--registry slowshield`; `cargo publish`, `yank` and `owner` need `--registry crates-io`.
- **"Yanked" can mean "held".** When only held versions satisfy a requirement, cargo says "is yanked". Tools that
  read yanked flags through SlowShield, such as cargo-deny, may report held versions as yanked.
- **Not covered:** git dependencies, `[patch]` with git, build scripts that download things, rustup toolchains, and
  alternative registries (`/cargo/<id>/` is kept free for them).
- **A crate deleted and published again under the same version** has a new checksum, which shows as tampering until
  an operator clears it.

## Code and tests

- `src/slowshield/ecosystems/cargo/index.py`: index paths, parsing (raw lines kept), the yank rewrite.
- `src/slowshield/ecosystems/cargo/service.py`: config.json, index files, publish times, policy, downloads.
- `src/slowshield/feeds/osv.py`: RustSec advisories.
- `tests/unit/test_cargo.py`, `tests/integration/test_cargo.py` (fake index and static host in `fakeupstream/`),
  `tests/e2e/test_stack.py::test_cargo_resolves_through_the_proxy` (real cargo), `tests/e2e/test_live.py` (nightly,
  against crates.io), perf scenarios `cargo_index` and `cargo_crate`.
