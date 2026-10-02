# Release-age policy

## The rule

A release becomes installable `delay_days` after it was published (default 7). The publish time is
taken from the registry: PyPI's per-file `upload-time` (PEP 700) and npm's `time[<version>]`.

* **PyPI is evaluated per file.** Uploading a new wheel to an old release does not make it
  installable early — each file waits for its own delay.
* **npm is evaluated per version.**
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

  Set `enforce_age_on_download = false` to only filter metadata (the behaviour of the Rust version).

## Fail-open

If **no** non-blocked file/version of a package is old enough (a brand-new package), SlowShield serves
all non-blocked ones instead of failing the install, adds `X-SlowShield-Fail-Open: 1`, and records a
`fail_open` event. Blocked versions are never served, even when failing open. Disable with
`fail_open = false` for strict environments.

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
age (`403` / hidden) → integrity. See [feeds.md](feeds.md).
