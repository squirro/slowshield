# Release-age policy

## The rule

A release becomes installable `delay_days` after it was published (default 7). The publish time is
taken from the registry: PyPI's per-file `upload-time` (PEP 700), npm's `time[<version>]`, and for Go the
`Last-Modified` of the version's `.mod` on proxy.golang.org, which is when the mirror first stored it. Go's own
`.info` `Time` is the commit time, which the author sets, and is never used ([design/go.md](design/go.md)). Maven
uses each file's `Last-Modified` on the repository, or when SlowShield first saw the version listed in the upstream
metadata, whichever is earlier ([design/maven.md](design/maven.md)). Cargo uses each version's `pubtime` in the
crates.io index; the first one SlowShield sees is kept, so a rewritten index can't move it earlier
([design/cargo.md](design/cargo.md)). Container images are judged per digest: a tag's digest by when the tag got it
(the registry's time where it has one, else SlowShield's first sight), a pinned digest by when a tag first pointed
to it ([design/oci.md](design/oci.md)).

* **PyPI is evaluated per file.** Uploading a new wheel to an old release does not make it
  installable early — each file waits for its own delay.
* **Maven is evaluated per file** (a classifier added to an old version later waits on its own), and its metadata
  per version. Too-new files get `425 Too Early`: Maven and Gradle show only the status line.
* **npm and Go are evaluated per version.** Go builds the exact versions go.mod requires, so a requirement that
  is too new fails with `403` instead of picking an older version.
* **Cargo is evaluated per version.** Too-new versions are marked yanked in the index, so cargo resolves to an older
  one; a Cargo.lock that pins one gets `403` with the version to use instead, as text cargo prints.
* **Container tags lag behind.** A tag resolves to the newest digest it has pointed to for the delay, so
  `nginx:latest` keeps working about a week behind; a pinned digest that is too new gets `403`.
* A file or version **without a publish time is treated as too new.**

## What clients see

* Index pages / packuments list only allowed files and versions. Responses carry
  `X-SlowShield-Held-Versions: <n>`.
* npm `dist-tags.latest` is recomputed as the highest allowed stable version; other tags whose target is
  held back are removed.
* Direct downloads of too-new artifacts (e.g. from a lockfile, `pip install <url>`, `npm ci`) get
  `403` with `Retry-After` and a JSON body:

  ```json
  {"error":"age_too_new","package":"granian","version":"2.8.4","published":"2026-09-30T15:10:15Z",
   "days_old":1.35,"delay_days_required":7.0,"retry_after_secs":488422}
  ```

  Set `enforce_age_on_download = false` to only filter metadata.

## Fail-open

If **no** non-blocked file/version of a package is old enough (a brand-new package), SlowShield serves
all non-blocked ones instead of failing the install, adds `X-SlowShield-Fail-Open: 1`, and records a
`fail_open` event. Blocked versions are never served, even when failing open. Disable with
`fail_open = false` for strict environments, or per ecosystem with `upstreams.<ecosystem>.fail_open`. Maven and Cargo
default to off: there, brand-new packages are the realistic attack (typosquats, impersonations, dependency
confusion). For container images, fail-open only applies during the instance's first `default_delay_days`, to tags
it has no history for yet: after that, a tag with nothing old enough is refused.

## Exceptions

```toml
[[exceptions]]          # a longer delay for a package with a history of incidents
ecosystem = "pypi"
package = "litellm"     # PyPI names are PEP 503-normalised, so "LiteLLM" matches too
delay_days = 14

[[exceptions]]          # release one reviewed version early
ecosystem = "npm"
package = "axios"
version = "1.15.1"
delay_days = 0
note = "urgent fix, reviewed"
```

Version-specific exceptions win over package exceptions, which win over `default_delay_days`.
Exceptions are reloaded live.

## Blocklist precedence

Order of checks for every request: package-level block (`451`) → version block (`451`) → release
age (`403` / hidden) → integrity. See [feeds.md](feeds.md). Container images answer `403` for all of these, because
containerd shows the message of a `403` only.

Operators add blocks of their own with `[[blocks]]` in config.toml (any ecosystem; for container images a
repository, tag or digest). They behave like feed entries and are listed with source `config`
([configuration.md](configuration.md#operator-blocks)).
