# Composer and PHP

Status: implemented. The protocol facts below were checked on 2026-10-24 against repo.packagist.org, the Packagist
and Composer sources on GitHub, and Composer 2.10.3 (the official `composer` image). The same day real Composer
2.10.3 ran against SlowShield in front of Packagist:

- `composer require monolog/monolog guzzlehttp/guzzle nette/schema` locked guzzle 8.2.0, nette/schema v1.3.6 and
  nette/utils v4.1.5 (8.3.0, v1.3.7 and v4.1.6 were under a week old) and monolog 3.12.1, and asked nothing but
  SlowShield;
- `composer require guzzlehttp/guzzle:8.3.0` found no such version;
- `composer install` from that lock, with vendor and Composer's cache removed, downloaded every dist from SlowShield;
- a lock pinning the held versions failed with `425` and SlowShield's warning;
- `composer audit` listed guzzle 7.4.4's 11 advisories with titles and CVEs.

The e2e test (`tests/e2e/test_stack.py::test_composer_installs_through_the_proxy`) runs Composer 2.10.3 through the
Compose stack against the fake Packagist.

SlowShield serves Packagist at `/composer/` as a Composer repository that replaces packagist.org. Versions younger
than the delay are left out of the metadata and refused on download, known malware is refused, and every dist is
checked against the fingerprint recorded on its first download, and against `dist.shasum` where Packagist has one.

## What Packagist provides (2026-10-24)

| What | Result |
|---|---|
| `packages.json` | `metadata-url` `https://repo.packagist.org/p2/%package%.json`, `providers-api`, `search`, `list`, `metadata-changes-url`, `notify-batch`, `security-advisories` (`metadata: true`, `api-url` `https://packagist.org/api/security-advisories/`), and `filter` (`metadata: true`, list `malware`, `summary-url` `https://repo.packagist.org/lists/all/summary.json`). `providers-url` and `packages: []` are left over from Composer 1, which Packagist shut down on 2025-09-01 |
| `p2/<vendor>/<package>.json` | Tagged versions only, newest first, as `{"minified": "composer/2.0", "packages": {"<name>": [...]}, "security-advisories": [...]}`. Minified means each entry holds only the keys that differ from the entry before it; `"__unset"` removes one. `Cache-Control: public, max-age=900`, `Last-Modified`, `ETag`. `304` on `If-Modified-Since`. An unknown package is a `404` with a short JSON string |
| `p2/<vendor>/<package>~dev.json` | The branches (`dev-main`, `2.x-dev`, …), in the same format. Composer asks for it only when the stability settings allow dev versions |
| Publish time | Every version has `published-time` once expanded (the minified format leaves it out when it equals the entry before). Packagist added it on 2026-06-12 "as the release cooldown / minimum-release-age reference": the creation time of the version's database row for a tag, the last update for a branch. Packagist keeps tagged versions immutable: a tag moved to another commit is blocked and audited, not updated. `time` is the date in the package's `composer.json` or of the commit, which the author controls. The oldest `published-time` in a sample was 2012-02-20 |
| `dist` | All 15,262 versions of the 100 most popular packages: `type: zip`, a URL `https://api.github.com/repos/<owner>/<repo>/zipball/<commit>`, `reference` the commit, and an empty `shasum`. api.github.com allows 60 unauthenticated requests per hour and answers `302` to `https://codeload.github.com/<owner>/<repo>/legacy.zip/<commit>`. Two downloads of monolog 3.12.1 from codeload gave the same bytes |
| `source` | `type: git`, the repository URL, `reference` the commit |
| Security advisories | Inline in each p2 file, partial: `advisoryId` and `affectedVersions`. The full ones (title, CVE, link) come from the `api-url`, which takes a POST form `packages[0]=…&packages[1]=…` (PHP's `http_build_query`) |
| Malware | The summary lists 162 packages with Composer constraints (`"*\|3.0.2\|3.0.4"`). Their p2 files are gone (`404`): Packagist deletes such packages. OSV's `Packagist` ecosystem holds one `MAL-*` entry |

Composer, read from its source (2.11) and checked with 2.10.3:

- **Dist URLs are tried in order, then given up.** A dist with `mirrors` gets the mirror URLs added before the
  original one, and a failed download moves on to the next URL. Since 2.10.0 a failed dist install no longer falls
  back to a `source` checkout (2.10 kept the `source-fallback` option to turn it back on; 2.11 removes it). Before
  2.10, a refused dist was cloned from GitHub instead.
- **Retries.** `425`, `500`, `502`, `503`, `504` are retried three times. 2.11 waits out a `Retry-After` of up to 60
  seconds and names a longer one in the error; 2.10.3 prints `(HTTP/1.1 425 Too Early)`.
- **`401` and `403` ask for credentials** for the host in an interactive terminal; non-interactive, `403` fails with
  "could not be accessed".
- **JSON bodies are shown.** The `warning` or `info` of a JSON response (`application/json`) with a status of 300 or
  higher, and of any p2 file or `packages.json`, is printed as `Warning from <host>: …`, once per attempt.
- **p2 files are revalidated with `If-Modified-Since`** on every run, using the `Last-Modified` stored with them.
- **`security-advisories` with `metadata: true` needs an `api-url`** (or `available-packages`); without either,
  Composer stops with "Invalid security advisory configuration".
- **`composer update --lock` writes only GitHub, GitLab and Bitbucket dist URLs** into a lock
  (`LockTransaction::updateMirrorAndUrls`), so it can't move a lock to SlowShield.
- **A repository named `packagist` is added next to packagist.org** by `composer config -g repos.packagist …` in
  2.10, not in its place: Composer then asked repo.packagist.org for every package too.
- **Composer's own cooldown** (2.11, `config.policy.cooldown.period`) is measured from `published-time` and errors out
  when a Composer repository leaves it out. It skips dev versions and locked packages that aren't being updated.
- **Malware filter.** Since 2.10.0, Composer blocks versions on a repository's `filter` lists (Packagist's
  `malware`), on install too.

## Client setup

```bash
composer config -g repo.packagist false
composer config -g repos.slowshield composer https://slowshield.example.com/composer/
```

In one project's `composer.json` instead:

```json
{
    "repositories": [
        {"type": "composer", "url": "https://slowshield.example.com/composer/"},
        {"packagist.org": false}
    ]
}
```

- **packagist.org must be off.** Composer asks every repository and takes a package from the first that has it, so
  a package SlowShield refuses would come from packagist.org.
- **Plain HTTP** (`http://localhost:8080/composer/`) needs `composer config -g secure-http false`.
- **Composer 2.10 or later.** Older versions clone a refused version from GitHub instead (see above).
- **Lockfiles name SlowShield.** A `composer.lock` written through SlowShield has SlowShield's dist URLs. One written
  against packagist.org has api.github.com URLs, and `composer install` downloaded them from GitHub, around
  SlowShield, even with packagist.org off. The Setup page has a PHP line that points a lock's dists at SlowShield
  and changes nothing else; a version SlowShield holds then fails with `425`. To leave SlowShield,
  `composer update --lock` against packagist.org writes GitHub's URLs back.
- **Not enforced by SlowShield:** `source` installs (`--prefer-source`, `preferred-install: source`), `vcs`, `path`
  and other repositories in a project's `composer.json`, lockfiles with GitHub URLs, Composer before 2.10, and
  plugins that download things themselves. Hard enforcement needs an egress firewall to github.com, api.github.com,
  codeload.github.com and repo.packagist.org.

## What clients see

| Path under `/composer/` | Behaviour |
|---|---|
| `packages.json` | Generated: `metadata-url` (`p2/%package%.json`), `security-advisories` (`metadata: true`, `api-url`), and the `malware` filter list with `summary-url` |
| `p2/<vendor>/<package>.json`, `p2/<vendor>/<package>~dev.json` | Packagist's file without the held and blocked versions, dist URLs pointing at SlowShield, minified again. `Last-Modified`, `ETag`, `304` on `If-Modified-Since` or `If-None-Match`, `X-SlowShield-Held-Versions`. `451` when the package is blocked as a whole, `404` when Packagist has no such package |
| `dists/<vendor>/<package>/<reference>.zip` | `451` when blocked or tampered, `425` with `Retry-After` when too new, else verified, streamed and cached |
| `api/security-advisories/` (POST) | Packagist's advisory API for the package names in the form, passed on unchanged, for `composer audit` |
| `lists/all/summary.json` | Packagist's malware summary, unchanged, so Composer's own malware filter keeps working |
| anything else | `404`, including `composer search`, which needs Packagist's search |

- **Names** are Packagist's: lower case `vendor/package`. A request in any other spelling is a `404`, as on
  Packagist.
- **Refusals** are JSON with a `warning`, which Composer prints:

  ```
  - Downloading guzzlehttp/guzzle (8.3.0)
  Warning from localhost:8080: slowshield: guzzlehttp/guzzle 8.3.0 is too new. It was published 2026-10-18T13:40:46Z
  (6.4 days ago); this proxy requires 7 days. It becomes available at 2026-10-25T13:40:46Z. Use an older version
  (composer update guzzlehttp/guzzle --with guzzlehttp/guzzle:8.2.0), or ask your SlowShield administrator for an
  exception.
  …
  The "http://localhost:8080/composer/dists/guzzlehttp/guzzle/b920e5fc….zip" file could not be downloaded
  (HTTP/1.1 425 Too Early)
  ```

  The suggested version is the newest one below the refused one that SlowShield would serve now.
- **`425` for too new, never `403`:** Composer asks for credentials on a `403`. It retries a `425` three times
  before it gives up.
- **Nothing old enough.** A p2 file whose every tagged version is held carries a `warning` that says so, since
  Composer would otherwise only report that no version matches. Branch files don't: with dev stability allowed,
  Composer asks for every package's branches.

## Held versions are removed

Composer has no flag like cargo's yanked, so a held or blocked version is left out of the p2 file and Composer
resolves to the newest version that is left. The rest of each entry is passed through: `published-time`, `time`,
`source`, `require`, `extra`. The file is expanded, filtered and minified again in Composer's format, so the next
entry's keys still diff against the right one. A version without a dist SlowShield can serve (no URL, or a reference
or type that can't name a file) is left out too, with a warning in the log.

`Last-Modified` must change whenever the filtered file changes, also when a held version comes of age or a block
appears, and Packagist's own `Last-Modified` doesn't. SlowShield keeps, per file and base URL, the `ETag` of the body
it served and when that body first appeared, in the metadata store, so every worker answers `If-Modified-Since` the
same way: `304` when the body hasn't changed since the client's date.

## Dist URLs are rewritten, not mirrored

Each served version's `dist.url` becomes `<public_url>/composer/dists/<vendor>/<package>/<reference>.zip`, and any
`mirrors` are dropped. Packagist's `mirrors` would keep lockfiles free of SlowShield's host, but Composer moves on to
the next URL when a mirror fails, and the next URL is GitHub: every refusal would turn into a download that goes
around SlowShield. With the URL itself rewritten, a refused download fails.

A download is judged by the versions whose dist names that reference in the package's p2 files (the tags first,
then the branches): it is refused when one of them is blocked, and served when one of them is served. A commit
holds the same files whatever the version is called. SlowShield fetches it from the version's own dist URL, except
that `https://api.github.com/repos/<owner>/<repo>/zipball/<ref>` (and `tarball`) is fetched from
`https://codeload.github.com/<owner>/<repo>/legacy.zip/<ref>`, where api.github.com redirects to: that skips
api.github.com's limit of 60 requests an hour. Such a GitHub URL must name the version's own `dist.reference`: the
dist is cached and fingerprinted under the reference, so an archive of another commit would be served for it. A
version whose URL names another commit is left out. Other hosts must be in `download_hosts`; a dist on another host
gets `502` with a warning that names the host and the setting. Dists are fetched over HTTPS only (`502` otherwise),
except from the host of `repo_url` itself when the administrator set that up over plain HTTP.

## Publish time

1. **Publish time = `published-time`,** which Packagist sets. `time` is never used: the author controls it.
2. **It never moves earlier.** The first plausible `published-time` seen for a version is kept in
   `package_versions`; when the file later states a different one, the later one counts.
3. **Without a `published-time`** (missing, or before 2011), the clock starts when SlowShield first sees the version
   (`first_listed`), and a warning is logged. As on NuGet, `first_listed` is recorded only for a version that has
   never had a plausible time. **A `published-time` in the future counts as now:** the version is held, and it isn't
   stored.
4. **The latest clock wins:** the current `published-time`, the first one stored, and `first_listed`.
5. **The stored times belong to a commit.** `package_versions` keeps the version's `dist.reference` with them; when a
   version names another commit, they start again. A branch's new commit, or a tag moved on a repository that allows
   it (a mirror, Satis), is timed by its own `published-time`, or from when SlowShield first sees it, never by the
   old commit's time. For an unchanged reference, the time never moves earlier.
6. **Branches** count from their last update, which is what `published-time` says for them: a branch pushed
   yesterday is held. Composer's own cooldown skips dev versions; SlowShield doesn't.

## Policy

- **Delay and exceptions:** the usual ones (`ecosystem = "composer"`), with the lower-case name and, for a version
  exception, any spelling of the version (`v1.2` matches `1.2.0`).
- **No fail-open by default** (`upstreams.composer.fail_open = false`), as for Maven, Cargo and NuGet: typosquats and
  dependency confusion are brand-new packages.
- **A pin that is too new is refused, not downgraded:** `425` on the download.
- **Downloads check the blocklist first.** A download names a reference, not a version, so a package blocked as a
  whole is refused before anything is fetched; version blocks are checked against the versions the reference
  belongs to.
- **Versions** compare as Composer compares them: the normalized form (`v1.2` is `1.2.0.0`, `1.0-beta2` is
  `1.0.0.0-beta2`) in PHP's `version_compare` order (`dev` < `alpha` < `beta` < `RC` < release < `patch`).

## Integrity

| Check | |
|---|---|
| Registry digest | `dist.shasum` (sha1) when Packagist has one; for GitHub dists it is always empty |
| Trust on first use | the sha256 of the bytes first served, per package and reference |
| Content | the `h1:` hash of the files in the zip (Go's dirhash), recorded with the first download |

GitHub builds archives on request, and in January 2023 a change to `git archive` changed the bytes of every one for
a day. When a later download's bytes differ from the first ones but the files in the zip are the same, SlowShield
records the new bytes and serves them, and logs a warning. Different files are tampering (`451`). The content check
needs the verified cache: with `cache.artifacts_enabled = false`, any change of bytes counts as tampering.

The zip is never modified.

## Malware feeds

- **OSV `Packagist`** (`MAL-*`) and **GitHub `composer`**, with Composer's version order. Both hold little today.
- **Packagist's malware list** is passed to Composer through `lists/all/summary.json`, so Composer 2.10 or later
  refuses those versions itself. Packagist deletes the packages, so their p2 files are `404` through SlowShield too.
  SlowShield doesn't import the list into its own blocklist.

## Security advisories

`composer audit` posts the package names to `api/security-advisories/`. SlowShield takes only valid package names
from the form (at most 1,000) and posts them to `advisories_url`, and returns Packagist's answer unchanged. The
advisories are information for Composer, not blocks; Composer 2.10 also refuses to lock a version with advisories
unless told otherwise, from the IDs inline in the p2 files.

## Shield wall

Followers take the leader's policy and `first_listed` times, as for every ecosystem; with `published-time` on every
version, `first_listed` is rarely used. The leader sends a `first_listed` per version name, not per commit: a
follower that already sees a newer commit of a branch than the leader does takes the leader's earlier time for it.
A follower fetches a dist through the leader only once it has a fingerprint
of its own (a dist has no registry digest to address it by), so each instance's first download of a reference comes
from GitHub. The leader compares the instances' first fingerprints byte for byte: two instances that got differently
archived bytes of the same commit show up as a mismatch.

## Configuration

```toml
[upstreams.composer]
enabled = true                                     # SLOWSHIELD_COMPOSER_ENABLED, Helm ecosystems.composer.enabled
fail_open = false
repo_url = "https://repo.packagist.org"            # p2 metadata and the malware summary
advisories_url = "https://packagist.org/api/security-advisories/"
download_hosts = ["codeload.github.com", "gitlab.com", "bitbucket.org"]
```

The URLs and `download_hosts` need a restart.

## Upstream load

| | Requests |
|---|---|
| A package | one GET of its p2 file per metadata TTL, then `If-None-Match` and `If-Modified-Since`; the `~dev` file only when a client asks for it |
| A dist | one GET to codeload.github.com (or the dist host) the first time; then the verified cache |
| `composer audit` | one POST to the advisory API per request (Composer asks about up to 500 packages at a time) |
| The malware summary | one GET per metadata TTL, then `If-Modified-Since` |

## Limitations

- **`composer search`** and the providers API aren't served, and nothing is sent to Packagist's download
  statistics.
- **Busy branches stay held** while they keep changing.
- **Lockfiles** carry SlowShield's host; see Client setup.
- **Private packages** stay in their own repositories in `composer.json`, ahead of SlowShield.

## Code and tests

- `src/slowshield/ecosystems/composer/version.py`: normalization and order.
- `src/slowshield/ecosystems/composer/metadata.py`: expanding, filtering, rewriting and minifying p2 files.
- `src/slowshield/ecosystems/composer/service.py`: routes, `packages.json`, publish times, policy, downloads,
  advisories.
- `tests/unit/test_composer.py`, `tests/integration/test_composer.py` (fake Packagist and codeload in
  `fakeupstream/`), `tests/e2e/test_stack.py::test_composer_installs_through_the_proxy` (real Composer).
