# RubyGems and Ruby

Status: implemented (https://github.com/squirro/slowshield/issues/17). The protocol facts below were checked on
2026-10-24 against rubygems.org and in the sources of Bundler 2.6.9 and RubyGems 3.6.9 (Ruby 3.4,
`ruby:3.4-slim`). What real clients did through SlowShield is under [Checked with real clients](#checked-with-real-clients).

SlowShield serves rubygems.org at `/rubygems/` as a compact index server. Bundler uses it as a mirror of
`https://rubygems.org`, and `gem` as its only source. Gem versions younger than the delay are left out of the
version lists and refused on download, known malware is refused, and every `.gem` is checked against the sha256 in
the compact index and against the fingerprint recorded on its first download.

## What rubygems.org serves (2026-10-24)

| What | Result |
|---|---|
| `GET /versions` (index.rubygems.org) | 24,233,723 bytes, 217,524 lines. A header `created_at: 2026-10-01T00:00:04Z` and `---`, then one line per gem, `<name> <v1>,<v2>,… <md5>`, where the md5 is the MD5 of that gem's `/info` file. The file is rebuilt about once a month (one line per gem); between rebuilds, every push or yank appends a line, which adds versions (`-1.0` removes one) and replaces the gem's md5 |
| `/versions` headers | `ETag` = the MD5 of the whole body, `Repr-Digest` and `Digest` `sha-256="…"`, `Accept-Ranges: bytes`, `Cache-Control: max-age=60, public`, `text/plain; charset=utf-8`. `Range: bytes=N-` gets a `206` with the same `ETag` and digest (of the whole file) |
| `GET /info/<name>` | `---`, then one line per published version and platform: `<version>[-<platform>] <dep>:<req>&<req>,…|checksum:<sha256>,ruby:<req>,rubygems:<req>,created_at:<ISO 8601 Z>`. Yanked versions are not listed. `ETag` = MD5 of the body (the same value as the gem's md5 in `/versions`), `Repr-Digest: sha-256`, `max-age=60` |
| `created_at` | Set by rubygems.org when the version is pushed; the pusher can't choose it. Each platform gem has its own (nokogiri 1.19.4: `x86_64-darwin` 15:18:44, `x86_64-linux-gnu` 15:18:50, the plain gem 15:18:58). Gems imported in 2009 say `2009-07-25` |
| Names | Case-sensitive: `/info/RedCloth` is a `200`, `/info/redcloth` a `404` |
| `GET /gems/<name>-<version>[-<platform>].gem` | `200` from rubygems.org itself (Fastly), no redirect, `application/octet-stream`, `max-age=31536000`. Its sha256 is the `checksum:` of the info line |
| `GET /quick/Marshal.4.8/<file>.gemspec.rz` | `200`, the gem's specification as zlib-compressed Ruby Marshal, immutable |
| `GET /specs.4.8.gz` | 6.3 MB, the full index of every name, version and platform, as gzipped Ruby Marshal. Also `latest_specs.4.8.gz` and `prerelease_specs.4.8.gz` |
| `GET /api/v1/dependencies?gems=rack` | `404`: the dependency API is switched off |

## What the clients do (Bundler 2.6.9, RubyGems 3.6.9)

- **Bundler** reads `/versions`, then `/info/<name>` for every gem it resolves, then downloads `/gems/<file>`. It
  keeps the files under `~/.bundle/cache/compact_index/<slug>/`.
  - **The md5 in `/versions` is only a hint.** Bundler asks for `info/<name>` again when the md5 differs from the MD5
    of its cached copy, and skips the request when they are equal. A mismatch is never an error.
  - **A gem missing from `/versions` is never asked for**: Bundler then treats it as not found.
  - **Digests are checked.** A response with `Repr-Digest` (or `Digest`) `sha-256` must match the whole file after
    writing, or Bundler fails with "The checksum of /info/… does not match the checksum provided by the server!".
    Without a digest header, Bundler never appends to `/versions` and downloads it whole each time.
  - **Appending.** `/versions` is asked for with `Range: bytes=<cached size - 1>-` and `If-None-Match`. A `206` is
    appended when its first byte matches the cached last byte and the digest of the result matches; otherwise
    Bundler asks again without `Range`. A `416` is asked again without `Range` too.
  - **Bundler 2.4 and older** check the `ETag` instead: it must be the MD5 of the body, quoted, or the request fails
    with the same checksum error. They send `Range` for `info/<name>` too.
  - **The cache slug comes from the original URI**, not from the mirror: a machine that used rubygems.org before
    has info files from rubygems.org, unfiltered, in the same cache directory.
  - **Fallbacks.** When `/versions` can't be read, Bundler tries the dependency API, then the full Marshal index
    (`specs.4.8.gz`). An HTTP error on `info/<name>` drops the compact index for the rest of the run and goes down
    the same path. A `403` on metadata reads as "Access token could not be authenticated".
  - **Gem files** are downloaded with RubyGems' fetcher: any status other than `200` is `bad response <reason>
    <code>`, retried three times. The body is not shown.
  - **Checksums.** The `checksum:` of the info line is compared with the sha256 of the downloaded `.gem`, and with
    the `CHECKSUMS` section of `Gemfile.lock` when the lockfile has one.
- **`gem install`** asks `HEAD <source>/versions`. If that works, it resolves with `info/<name>` and
  `quick/Marshal.4.8/<file>.gemspec.rz`, and downloads `gems/<file>`. If it doesn't, it falls back to the full
  Marshal index. It reads no digests or ETags.
- **`gem search`, `gem list --remote`, `gem outdated`, `gem update` and `gem update --system`** read the full
  Marshal index (`specs.4.8.gz`, `latest_specs.4.8.gz`, `prerelease_specs.4.8.gz`), with no compact index option.

## Client setup

Bundler, for every project on the machine:

```bash
bundle config set --global mirror.https://rubygems.org https://slowshield.example.com/rubygems
```

`gem`, in `~/.gemrc` (or the system-wide `gemrc`):

```yaml
---
:sources:
- https://slowshield.example.com/rubygems/
```

- **A mirror, not a new `source`.** Gemfiles keep `source "https://rubygems.org"`, and `Gemfile.lock` keeps
  `remote: https://rubygems.org/` and its checksums, so a project builds the same with or without SlowShield.
- **No `fallback_timeout`.** With `mirror.https://rubygems.org.fallback_timeout` set, Bundler goes to rubygems.org
  when SlowShield doesn't answer in time.
- **Not `mirror.all`**: that would send private gem servers to SlowShield too.
- **The mirror applies to `https://rubygems.org` only.** A Gemfile with `source "http://rubygems.org"` is not
  mirrored.
- **Environment variables don't work well.** Bundler's variable for the mirror is
  `BUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/`, which shells can't `export` and Kubernetes doesn't accept. The Setup page
  gives the `bundle config` command for CI and Dockerfiles; the official `ruby` images read `~/.bundle/config`.
- **`gem sources --add`** writes the same `~/.gemrc`, but asks for confirmation for an `http://` source. Remove
  rubygems.org with `gem sources --remove https://rubygems.org/`, or `gem` asks it too.
- **Plain HTTP.** `http://localhost:8080/rubygems` works with local HTTP, for both clients.

## What clients see

| Path under `/rubygems/` | Behaviour |
|---|---|
| `versions` | rubygems.org's `/versions` with every md5 written as 32 zeros (see below). `ETag` = MD5 of the served body, `Repr-Digest: sha-256`, `Range` answered with `206`, `304` on `If-None-Match` |
| `info/<name>` | upstream lines byte for byte, without the versions that are too new or blocked. `ETag` = MD5 of the served body, `Repr-Digest: sha-256`, `304` on `If-None-Match`, `X-SlowShield-Held-Versions`. A gem blocked as a whole, or with nothing old enough, is an empty list (`---`) |
| `names` | rubygems.org's `/names`, unchanged (names only) |
| `gems/<file>.gem` | `425` with `Retry-After` when too new, `451` when blocked or tampered, else verified, streamed and cached |
| `quick/Marshal.4.8/<file>.gemspec.rz` | `425`/`451` as for the gem; else rubygems.org's file, cached |
| `specs.4.8.gz`, `latest_specs.4.8.gz`, `prerelease_specs.4.8.gz`, `Marshal.4.8`, `api/…` | `404` with a plain-text reason: these can't be filtered by age |
| anything else | `404` |

`/versions` and `/info` carry `Cache-Control: no-transform`, so the Caddy edge (and any proxy that honours it) doesn't
compress them: a compressed body changes the `ETag`, which breaks Bundler 2.4 and older, and its `Repr-Digest` would
no longer describe the bytes the client checks.

What the clients print:

- **A held version, new resolution** (`bundle update`, `bundle add`, `gem install` without `-v`): the newest version
  SlowShield serves, without a message.
- **A held version pinned in `Gemfile.lock`**: Bundler can't find it in the index and says that the author removed it
  ("Your bundle is locked to rack (3.2.7) …, but that version can no longer be found in that source"). `bundle
  update rack` picks the newest allowed version.
- **`gem install rack -v 3.2.7`** (held): "Could not find a valid gem 'rack' (= 3.2.7)".
- **A gem blocked as a whole, or brand new**: "Could not find gem 'x' in rubygems repository https://rubygems.org/"
  (Bundler) or "Could not find a valid gem 'x'" (`gem`). The block is on the Security page.
- **A download that is refused** (a lockfile resolved elsewhere, a stale cache, curl): `bad response Too Early 425`
  or `bad response Unavailable For Legal Reasons 451`. Neither client shows the body; curl does.

The refusal codes match Maven's and NuGet's: `425` because a `403` on Bundler's metadata path reads as a credentials
problem, and RubyGems prints the reason phrase, "Too Early", which says what happened.

## The `/versions` file

Bundler needs every gem name in `/versions`, so SlowShield keeps a copy of the whole file:

1. **Every md5 becomes `00000000000000000000000000000000`.** It can't stay rubygems.org's: on a machine that used
   rubygems.org before, Bundler's cached info files have exactly that MD5, so Bundler would skip SlowShield's
   filtered file and resolve from the unfiltered one. It can't be the MD5 of SlowShield's filtered info file either:
   that changes whenever a version ages in, which would rewrite lines in the middle of an append-only file. Zeros
   never match a real file, so Bundler always asks for `info/<name>`, with `If-None-Match`; SlowShield answers `304`
   when nothing changed.
2. **Same length, so the same byte offsets.** The md5 column has a fixed width, so SlowShield's file is exactly as
   long as rubygems.org's and stays append-only between rebuilds.
3. **The version lists in `/versions` stay as they are**, held versions included. Both clients resolve from
   `info/<name>`; `/versions` tells them which gems exist.
4. **Kept up to date with Range requests.** When a client asks and the copy is older than a minute (rubygems.org's
   `max-age`), SlowShield asks rubygems.org for `Range: bytes=<size - 1>-` with `If-None-Match`, appends the new
   lines, and checks rubygems.org's `Repr-Digest` against its own copy of the upstream bytes. A mismatch (the
   monthly rebuild) gets the whole file again. One minute between checks, shared by all workers; while rubygems.org
   is unreachable, the last copy is served.
5. **On disk**, under `<data_dir>/rubygems/`: the upstream bytes, the served bytes and their digests, written by one
   worker at a time (a file lock), read by all.
6. **Range from clients.** A start inside the file gets a `206` from there; a start past the end (a cache filled
   by rubygems.org or another instance) gets the whole file. Bundler's digest check sorts out the rest: a tail that
   doesn't fit its cached file makes it ask for the whole file.

## Held versions are left out

RubyGems has no "yanked" marker in the compact index (yanked versions are removed), so there is nothing like
Cargo's yank rewrite. A held or blocked line is left out of `info/<name>`.

- **The lines that remain are rubygems.org's bytes**, `checksum:` and `created_at:` included, so Bundler's checksum
  checks and `Gemfile.lock` `CHECKSUMS` see what rubygems.org publishes.
- **When the hold ends** the file, its MD5 and its `ETag` change, and the next `bundle update` sees the version.
- **Lockfile pins can't reach the download check**: Bundler finds the pinned version missing from the index before
  it downloads anything (see What clients see). The download check stays for clients that skip the index.

## Platform gems

Each line of an info file is a version and a platform (`1.19.4`, `1.19.4-x86_64-linux-gnu`, `1.19.4-java`), pushed
on its own, with its own `created_at` and `checksum`. SlowShield judges each line by its own time:

- A platform gem pushed today for a version that is a year old is held like a new version. Bundler prefers the
  platform gem for the machine, so this is the realistic way to slip new code under an old version number.
- `package_versions` has a row per line, keyed by the line's version-and-platform string, as Bundler names the file
  (`1.19.4-x86_64-linux-gnu`); the UI lists platform gems as their own versions.
- Blocks and exceptions name versions (`1.19.4`) and cover every platform of that version.
- A download names a file, `<name>-<version>[-<platform>].gem`. Gem names may contain `-`, so SlowShield finds the
  line by trying each split before a digit, in the gem's info file.

## Publish time

1. **Publish time = the line's `created_at`**, from the info file SlowShield fetches anyway. No extra request, and
   no rubygems.org API (`/api/v1/versions/<name>.json` has the same `created_at`).
2. **It never moves earlier.** The first `created_at` seen for a line is kept in `package_versions`. If the file later
   states another one, the later of the two counts.
3. **Without a plausible `created_at`** (missing, unreadable, before 2004, or in the future), the clock starts when
   SlowShield first sees the line (`first_listed`), and a warning is logged.
4. **A line that disappears** (yanked) is recorded as yanked; if the same version is pushed again, its new
   `created_at` is later than the old one, so it waits.

## Policy

- **Delay and exceptions:** the usual ones (`ecosystem = "rubygems"`). Gem names are matched exactly as spelled
  (rubygems.org's names are case-sensitive).
- **Versions** are ordered as `Gem::Version` orders them (`1.0.a` < `1.0`; a letter makes a prerelease), for
  advisory ranges and exception ranges. An exact version matches as spelled.
- **No fail-open by default** (`upstreams.rubygems.fail_open = false`), like Cargo and NuGet: RubyGems malware is
  mostly brand-new gems (typosquats), so a gem with nothing old enough is held.

## Integrity

| Check | |
|---|---|
| Registry digest | the info line's `checksum:` (sha256 of the `.gem`), checked while streaming |
| Size | `Content-Length` |
| Trust on first use | the sha256 of the bytes first served, per file |

- **The download must match a line in the gem's current info file**, or it is a `404`.
- **Bytes are never changed**, so the gem's own signature (rarely used, `gem cert`) and Bundler's checksum checks
  work as with rubygems.org.
- **`.gemspec.rz`** files have no published digest. They are fetched once and kept; the `.gem` that follows is
  checked, and RubyGems installs from the specification inside the `.gem`.
- **Shield wall.** A follower fetches `.gem` files through its leader (they have a sha256) and reads the index
  itself; `first_listed` times travel like Cargo's and NuGet's.

## What can go around SlowShield

- **Sources other than rubygems.org.** Gemfile `source` blocks for other servers, `git:` and `github:` gems, and
  `path:` gems are fetched directly. So is `gem install --source …` or `--clear-sources`.
- **`fallback_timeout`** on the mirror (see Client setup).
- **The dependency API and the full Marshal index** are not served, so neither client can fall back to an
  unfiltered list through SlowShield.
- **An unfiltered Bundler cache** from rubygems.org can't be used, because no md5 in `/versions` matches it.
- **`gem push`, `yank` and `owner`** talk to rubygems.org's API directly: publishing, not installing.

An egress firewall that allows only SlowShield is the hard guarantee, as for every ecosystem.

## Malware feeds

- **OSV `RubyGems` (`MAL-*`) and GitHub (`rubygems`)**, as for every ecosystem. On 2026-10-24 OSV's `RubyGems/all.zip`
  was 5.2 MB.
- **Why the blocklist matters here.** rubygems.org yanks malicious gems, usually within days. The blocklist covers
  that time, keeps a yanked name blocked if it comes back, and turns a lockfile that still names it into a security
  event.

## Configuration

```toml
[upstreams.rubygems]
enabled = true                               # SLOWSHIELD_RUBYGEMS_ENABLED, Helm ecosystems.rubygems.enabled
fail_open = false
index_url = "https://index.rubygems.org"     # /versions, /info/<name>, /names
download_url = "https://rubygems.org"        # /gems/<file>.gem, /quick/Marshal.4.8/<file>.gemspec.rz
download_hosts = []
```

`index_url`, `download_url` and `download_hosts` decide which hosts SlowShield may reach, so changing them needs a
restart.

## Upstream load

| | Requests |
|---|---|
| Startup, background | none (the OSV feed already downloads `RubyGems/all.zip`) |
| `/versions` | 24 MB once (and once a month after the rebuild); then at most one `Range` request a minute while clients ask, usually a few kB |
| A gem's info file | one GET per metadata TTL, then `If-None-Match` (a `304` when unchanged), shared by all clients and workers |
| Publish times | none |
| A `.gem` or `.gemspec.rz` | one GET, the first time; then the cache |
| rubygems.org API | none |

For clients the zeros cost one conditional request per gem per `bundle install`, answered by SlowShield (`304`), where
rubygems.org would let Bundler skip unchanged gems. A first `bundle install` downloads the 24 MB `/versions`
uncompressed.

## Limitations

- **Commands that need the full Marshal index**: `gem search`, `gem list --remote`, `gem outdated`, `gem update` and
  `gem update --system` fail with `bad response Not Found 404`. Bundler's `bundle outdated` and `bundle update` work.
  Filtering that index would need publish times for every gem on rubygems.org.
- **A lockfile pin of a held version** gets Bundler's "can no longer be found" message, not SlowShield's reason.
- **`/versions` still lists held version numbers.** Tools that read it directly see them.
- **Other gem servers** (gem.coop, private servers, GitHub Packages) are not covered; `/rubygems/<id>/` is kept free
  for them.
- **A gem yanked and pushed again under the same version** has a new checksum, which shows as tampering until an
  operator clears it.

## Code and tests

- `src/slowshield/ecosystems/rubygems/index.py`: info files (parsing with raw lines kept, rendering), file names.
- `src/slowshield/ecosystems/rubygems/versions_file.py`: the `/versions` copy, its updates and Range answers.
- `src/slowshield/ecosystems/rubygems/version.py`: `Gem::Version` order.
- `src/slowshield/ecosystems/rubygems/service.py`: paths, publish times, policy, downloads, refusals.
- `tests/unit/test_rubygems.py`, `tests/integration/test_rubygems.py` (fake compact index and gem host in
  `fakeupstream/`), `tests/e2e/test_stack.py::test_rubygems_installs_through_the_proxy` (real Bundler and `gem`).
