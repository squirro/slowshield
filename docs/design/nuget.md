# NuGet and C#

Status: implemented (https://github.com/squirro/slowshield/issues/38). The protocol facts below come from a spike on
2026-10-08 against api.nuget.org and the .NET SDK 10.0.401 (`mcr.microsoft.com/dotnet/sdk:10.0`). The same day the
service was checked twice:

- **Against nuget.org**, in process: the generated service index, Newtonsoft.Json's flat container and inlined
  pages, AWSSDK.Core's 24 linked pages recomputed, a verified Newtonsoft.Json 13.0.1 download, `425` for the
  unlisted 13.0.5-beta1, search, and the vulnerability files.
- **With real dotnet 10.0.401** against SlowShield and the fake registry: `dotnet restore` resolved a dependency
  to the newest allowed version and NuGetAudit reported the fake vulnerability (`NU1903`); a reference to a held
  version failed with `NU1103` (the next version up was a prerelease); `dotnet add package` without a version
  picked the newest allowed version from inlined and from linked registration pages; `dotnet package search`
  left out held and blocked versions; a blocked package failed with `451` (`NU1301`).

The e2e test (`tests/e2e/test_stack.py::test_nuget_restores_through_the_proxy`) runs the same client through the
Compose stack. It hasn't run yet.

SlowShield serves nuget.org at `/nuget/`. NuGet has no release-age setting of its own, so SlowShield's delay is the
only one. Versions younger than the delay are left out of the version lists and refused on download, known malware is
refused, and every `.nupkg` is checked against nuget.org's `packageHash` and against the fingerprint recorded on its
first download.

## Spike results (2026-10-08)

Checked with curl and Python against api.nuget.org, and with `dotnet restore` 10.0.401 against a small test server
that refused two Newtonsoft.Json versions and passed everything else through.

| What | Result |
|---|---|
| Service index | `https://api.nuget.org/v3/index.json`, `"version": "3.0.0"`, `Cache-Control: max-age=21600`. Flat container: `PackageBaseAddress/3.0.0` at `https://api.nuget.org/v3-flatcontainer/`. SemVer 2 registration hive: `RegistrationsBaseUrl/3.6.0` and `RegistrationsBaseUrl/Versioned` (with `"clientVersion": "4.3.0-alpha"`) at `https://api.nuget.org/v3/registration5-gz-semver2/`. `VulnerabilityInfo/6.7.0` at `https://api.nuget.org/v3/vulnerabilities/index.json`. `SearchQueryService` (plus `/3.0.0-beta`, `/3.0.0-rc`, `/3.5.0`) at `https://azuresearch-usnc.nuget.org/query` and `-ussc`. `Catalog/3.0.0` at `https://api.nuget.org/v3/catalog0/index.json` |
| Flat container | `<base>/<id>/index.json` is `{"versions": [...]}`: lower-case normalized versions in version order, unlisted ones included (Newtonsoft.Json: 86 versions, including the unlisted `13.0.5-beta1`). `<base>/<id>/<ver>/<id>.<ver>.nupkg` and `<base>/<id>/<ver>/<id>.nuspec`. Only the lower-case id and version work: `Newtonsoft.Json/index.json`, `Newtonsoft.Json.13.0.1.nupkg` and `13.0.1.0` are `404` (Azure `BlobNotFound`, an XML body) |
| `.nupkg` response | `application/octet-stream`, `Content-Length`, `x-ms-meta-sha512` (the same value as `packageHash`), `Cache-Control: public, max-age=86400`. The zip holds `.signature.p7s`, the repository signature |
| Registration paging | Pages of up to 64 versions. With at most 128 versions the pages are inlined: Newtonsoft.Json (86 versions) has two inlined pages, `@id` `…/newtonsoft.json/index.json#page/3.5.8/12.0.1-beta2`. Above that, each page is a separate document: AWSSDK.Core has 24 pages, `@id` `…/awssdk.core/page/3.0.0-preview/3.3.5.json`, with `count`, `lower`, `upper` and no `items` in the index. A page document has `items`, `parent` (the index URL), `lower`, `upper`, `count` |
| Registration bodies | `Content-Encoding: gzip`, `application/json`. An unknown id is a `404` |
| Registration leaf | `@id` (`…/newtonsoft.json/14.0.1-beta2.json`), `catalogEntry` (inlined, with `@id` pointing at the catalog leaf, `version`, `listed`, `published`, `packageContent`, `dependencyGroups`, `deprecation`, `vulnerabilities`, `iconUrl`, …), `packageContent`, `registration` |
| Unlisted version | `published` is `1900-01-01T00:00:00+00:00` in the registration and `1900-01-01T00:00:00Z` in the catalog leaf, with `"listed": false`. The catalog leaf still has the real upload time in `created` (`13.0.5-beta1`: created 2025-12-30). Newtonsoft.Json has 31 unlisted versions. Editing metadata changes `lastEdited`, not `published` (13.0.1: published 2021-03-22, lastEdited 2022-12-08) |
| `packageHash` | Only in the catalog leaf (`https://api.nuget.org/v3/catalog0/data/<timestamp>/<id>.<version>.json`), not in the registration: `packageHash` (base64 SHA512), `packageHashAlgorithm: "SHA512"`, `packageSize`. For Newtonsoft.Json 13.0.1 the SHA512 of the downloaded bytes, the catalog's `packageHash` and the blob's `x-ms-meta-sha512` are equal, and the size matches `packageSize` |
| Search | `{"totalHits", "data": [...]}`. A result has `@id` and `registration` (the SemVer 2 registration index), `id`, `version` (the newest), `versions` (listed versions only, each with an `@id` at its registration leaf), `vulnerabilities`, `totalDownloads` |
| Vulnerabilities | The index lists two files (`base` and `update`) under `https://api.nuget.org/v3-vulnerabilities/<timestamp>/…`, 36 kB and 283 bytes gzipped |
| `dotnet restore`, `425` | `Response status code does not indicate success: 425 (Too Early).`, then `The feed 'nuget.org […]' lists package 'Newtonsoft.Json.13.0.1' but multiple attempts to download the nupkg have failed.` Exit code 1. The body is not shown. 6 requests in 5.6 seconds: `Retry-After: 172800` is not honoured |
| `dotnet restore`, `451` | The same, with `451 (Unavailable For Legal Reasons)`. 6 requests |
| What restore asks for | The service index and the flat container only (`<id>/index.json`, then the `.nupkg`). No registration |
| `dotnet add package` without a version | The registration index and every page that isn't inlined, then the flat container |
| A version missing from the flat container | `Version="13.0.1"` (a minimum) resolves the next version up with warning `NU1603: … Newtonsoft.Json 13.0.1 was not found. Newtonsoft.Json 13.0.3 was resolved instead.` An exact `[13.0.1]` fails with `NU1102: Unable to find package Newtonsoft.Json with version (= 13.0.1)` |
| Plain HTTP | An `http://` source fails with `NU1302` unless the source has `allowInsecureConnections="true"` |
| `<clear/>` and a source named `nuget.org` | Restore asked only that source |

What the spike did not check, so it is unverified:

- What happens to `published` when an unlisted version is relisted. The design doesn't depend on it.
- Visual Studio, Rider and `nuget.exe`. Only the .NET SDK was run.
- How the client treats a `SearchQueryService` that drops results. Only the response format was checked.
- NuGet's repository signature validation through SlowShield. The bytes don't change, so it should behave as with
  nuget.org.
- `packages.lock.json` (`contentHash`) and `RestoreLockedMode` through SlowShield.
- `packageSourceMapping` with SlowShield's source.

The earlier NuGet notes in [routing.md](routing.md) and [research/ecosystems.md](../research/ecosystems.md) were
written from memory. Checked against the spike:

- `<clear/>` plus one source: confirmed. Restore asks only that source.
- Publish time from the registration `published`: confirmed, with `1900-01-01` for unlisted versions.
- Filtering the flat container `index.json` too: confirmed and needed, since restore reads only the flat container.
- The repository signature inside the `.nupkg`: confirmed (`.signature.p7s`). The lockfile's SHA512 is not
  verified.
- Rewriting "every absolute `@id`": not done. SlowShield rewrites the URLs a client follows to packages and
  registrations, and leaves catalog and icon URLs alone (see What clients see).
- "Extra NuGet sources" falling back to nuget.org: not tested here. NuGet asks every enabled source, which is why
  `<clear/>` is required.

## Client setup

```xml
<!-- NuGet.Config: ~/.nuget/NuGet/NuGet.Config, %AppData%\NuGet\NuGet.Config, or next to a solution -->
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="nuget.org" value="https://slowshield.example.com/nuget/v3/index.json" />
  </packageSources>
</configuration>
```

- **`<clear/>` is required.** NuGet asks every enabled source and takes the first good answer, so an enabled nuget.org
  bypasses everything.
- **The source is named `nuget.org`,** so `packageSourceMapping` entries that name `nuget.org` keep working.
- **Plain HTTP** (`http://localhost/nuget/v3/index.json`) needs `allowInsecureConnections="true"` on the source.
- **Fail the build on `NU1603`.** A `PackageReference` to a held version restores the next version up, with only
  that warning (see One snapshot per package). Set `TreatWarningsAsErrors`, or add `NU1603` to `WarningsAsErrors`.
  The Setup page has a `Directory.Build.props` for it:

  ```xml
  <Project>
    <PropertyGroup>
      <WarningsAsErrors>$(WarningsAsErrors);NU1603</WarningsAsErrors>
    </PropertyGroup>
  </Project>
  ```

- **Not enforced by SlowShield:** a repository `NuGet.Config` that adds nuget.org again, `--source` on the command
  line, and packages already in the global packages folder (`~/.nuget/packages`). Hard enforcement needs an egress
  firewall to api.nuget.org.

## What clients see

All under `/nuget/`. SlowShield writes the service index itself and lists only what it serves. `/nuget/<id>/` stays
free for later feeds (`v3` is taken).

| Path under `/nuget/` | Behaviour |
|---|---|
| `v3/index.json` | Generated: `PackageBaseAddress/3.0.0` (`v3/flatcontainer/`), `RegistrationsBaseUrl/3.6.0` (`v3/registration/`, one SemVer 2 hive), `VulnerabilityInfo/6.7.0`, `SearchQueryService` (also `/3.0.0-beta`, `/3.0.0-rc`, `/3.5.0`) |
| `v3/flatcontainer/<id>/index.json` | The versions of the package snapshot, without the held and blocked ones, lower-case and normalized, in NuGet's version order. `451` when the package is blocked as a whole |
| `v3/flatcontainer/<id>/<ver>/<id>.<ver>.nupkg` | `451` when blocked or tampered, `425` with `Retry-After` when too new, else verified, streamed and cached. `HEAD` is checked the same way |
| `v3/registration/<id>/index.json` | The registration index of the snapshot. Held and blocked versions are removed, every page's `count`, `lower` and `upper` are recomputed, and empty pages are dropped. Pages nuget.org inlines stay inlined |
| `v3/registration/<id>/page/<lower>/<upper>.json` | A page that isn't inlined, from the same snapshot |
| `v3/registration/<id>/<ver>.json` | A registration leaf for a version that is served, else `404` |
| `v3/vulnerabilities/index.json`, `v3/vulnerabilities/<file>` | nuget.org's vulnerability data, unchanged except for its URLs, so NuGetAudit keeps working |
| `v3/query` | nuget.org search, with held and blocked versions removed from each result |
| anything else | `404`, including the `.nuspec` |

- **Spellings.** Ids are lower-case. Versions are in NuGet's normalized form: `1.0` and `1.0.0.0` are `1.0.0`,
  leading zeros go (`1.01` is `1.1.0`), a fourth part of `0` is dropped, build metadata is dropped, and the
  prerelease label is lower-case. Package ids, the publish-time records, exceptions, blocklist matches, the held set
  and the artifact key all use that form. A request path in any other spelling is a `404`, as on nuget.org.
- **Rewritten URLs.** The registration index, page and leaf `@id`s, `parent`, `registration`, and `packageContent`
  (on the leaf and in its `catalogEntry`), and in search results `@id`, `registration` and each version's `@id`.
  Catalog `@id`s, `iconUrl`, `licenseUrl`, `readmeUrl` and the rest stay as nuget.org wrote them: SlowShield doesn't
  serve the catalog or icons, so Visual Studio loads icons from nuget.org.
- **Refusals are plain text.** `dotnet` shows only the status line, so the text is for people using curl and for the
  logs. `403` is never used: NuGet may read it as a credentials problem.

## One snapshot per package

Every response about a package comes from one snapshot of its registration: the index plus every page that isn't
inlined. The flat container list is built from the same snapshot, so the two lists always agree, and the flat
container `index.json` on nuget.org is never fetched.

1. **Fetch** the index. Pages without `items` are fetched too, but only from under `registration_url`.
2. **Store** the index and pages together in the metadata store, with the index's `ETag`. When the index answers
   `304`, the stored pages are used again: nuget.org rewrites the index (its `commitId` changes) whenever a page
   changes.
3. **Judge** every version, then render. A held or blocked version is removed from its page; pages are counted and
   bounded again in NuGet's version order, and an empty page is dropped.
4. **Upstream down:** the stored snapshot is served (stale), else `503` with `Retry-After`.
5. **A page request** that names bounds the current snapshot no longer has (the snapshot changed after the client
   read the index) gets the served versions within those bounds, so the client still sees a consistent result.

Why versions are removed instead of marked, as cargo's are marked yanked: the flat container, the only list restore
reads, has no flag to set. It lists unlisted versions like any other, as the spike showed. Removing the version
makes a minimum-version reference resolve the next version up, with warning `NU1603`, as the spike also showed. When the next version up is a prerelease, restore finds nothing and fails with `NU1103`. That version is
normally newer still and therefore held too, but on a package with several maintained
lines (6.0.30 released yesterday, 7.0.0 a year ago) restore moves to the next line. So the build should fail on
`NU1603`: `TreatWarningsAsErrors`, or `NU1603` in `WarningsAsErrors`, as the Setup page recommends. A lock file
also keeps the version from changing.

## Publish time

1. **Publish time = `published`** in the registration leaf, which nuget.org sets when the version is published.
2. **It never moves earlier.** The first plausible `published` seen for a version is kept in `package_versions`. If
   the registration later states a different one, the later of the two counts.
3. **Without a plausible `published`** (missing, `1900-01-01` for unlisted versions, before 2010, or in the future),
   now or stored, the clock starts when SlowShield first sees the version listed (`first_listed`), and a warning is
   logged.
4. **The latest clock wins:** the current plausible `published`, the first one stored and `first_listed`. This is
   cargo's rule (`_record` stores `first_listed` only for a version without a plausible time; `_published` takes the
   maximum of all three). A version first seen unlisted and relisted later is therefore timed from when SlowShield
   first saw it, whatever `published` says after relisting. Maven's rule, where the earlier of two clocks counts, is
   not used: `first_listed` is a fallback here, not a second opinion.
5. **Unlisting doesn't restart the clock.** One difference from cargo: cargo records `first_listed` whenever the
   current line has no plausible time, even if an earlier one was stored. On nuget.org that would happen every time
   a version is unlisted (`published` becomes `1900-01-01`) and would hold an old, pinned version again for the full
   delay. SlowShield records `first_listed` only for a version that has never had a plausible `published`. So a
   version that is unlisted and listed again keeps the clock it had, its first `published` or its first
   `first_listed`; this differs from cargo on purpose.
6. **Per version,** like npm and Cargo. No extra requests.

A fresh SlowShield holds an unlisted version for the full delay, even an old one: its `published` is `1900-01-01`,
and the catalog's `created` isn't used.

## Policy

- **Delay and exceptions:** the usual ones (`ecosystem = "nuget"`), with the lower-case id and, for a version
  exception, any spelling of the version (`1.0` matches `1.0.0`).
- **No fail-open by default** (`upstreams.nuget.fail_open = false`), as for Maven and Cargo: typosquats and
  dependency confusion are brand-new packages, and builds pin versions.
- **A pin that is too new is refused, not downgraded:** `425` on the download.
- **Downloads check the blocklist first,** before anything is fetched, so a package nuget.org has deleted since still
  shows up as a blocked download and a security event, not a `404`.

## Integrity

| Check | |
|---|---|
| Registry digest | the catalog leaf's `packageHash` (base64 SHA512), checked while streaming through `Expected.sha512` |
| Size | `packageSize` from the catalog leaf, and `Content-Length` |
| Trust on first use | the sha256 of the bytes first served, per package version |

- **The catalog leaf** is the one the registration names in `catalogEntry.@id`, fetched from under `catalog_url`
  only, once per version (catalog leaves don't change; a new commit gets a new URL). Without a `packageHash` the
  download is a `503`.
- **The `.nupkg` is never modified.** The repository signature (`.signature.p7s`) is inside it.
- **Re-signing is tampering.** When nuget.org re-signs a package, its bytes, its sha256 and the catalog's
  `packageHash` all change. The new bytes match the new `packageHash`, but not the fingerprint recorded on the first
  download, so SlowShield refuses them (`451`) and records a `tampered` event until an operator clears it.
- **Version spelling upstream.** The download goes to `<flat_container_url>/<id>/<ver>/<id>.<ver>.nupkg` with the
  lower-case normalized version, as the snapshot names it.

## Search

`v3/query` is passed to `search_url` with the client's query string (`take` capped at 100). For each result,
SlowShield builds that package's snapshot (cached, at most eight at a time) and removes held and blocked versions from
`versions`. `version` becomes the newest version left, and a result with nothing left is dropped, as is a package
blocked as a whole or one whose snapshot can't be fetched (fail closed). `totalHits` goes down by the number of
results dropped from the page.

## Vulnerability data

`v3/vulnerabilities/index.json` is nuget.org's index with each file's `@id` pointing at SlowShield. A file is served
only if the current index lists it. The data is advisory information for NuGetAudit and is passed through unchanged.

## Malware feeds

OSV `NuGet` (`MAL-*`) and GitHub `nuget`. Versions follow NuGet's own order (`NuGet.Versioning`'s `VersionComparer`,
ported with its test cases): numeric parts first, then a fourth part, a release sorts above its prereleases, labels
compare part by part, numbers below text, text without regard to case. Exact matches compare normalized versions, so
an advisory for `1.0` also blocks `1.0.0`.

## Configuration

```toml
[upstreams.nuget]
enabled = true                                                     # SLOWSHIELD_NUGET_ENABLED, Helm ecosystems.nuget.enabled
fail_open = false
flat_container_url = "https://api.nuget.org/v3-flatcontainer/"
registration_url = "https://api.nuget.org/v3/registration5-gz-semver2/"
catalog_url = "https://api.nuget.org/v3/catalog0/"                 # packageHash
vulnerability_url = "https://api.nuget.org/v3/vulnerabilities/index.json"
search_url = "https://azuresearch-usnc.nuget.org/query"
```

The URLs come from the config and are not read from nuget.org's service index, so the hosts SlowShield may reach stay
fixed. Changing them needs a restart. `catalog_url` isn't one of the four resources clients see; it is there because
`packageHash` is only in the catalog.

## Upstream load

| | Requests |
|---|---|
| Startup, background | none (the OSV feed already downloads `NuGet/all.zip`) |
| A package's snapshot | one GET of the registration index per metadata TTL, then `If-None-Match`; one GET per page that isn't inlined, only when the index changed (packages with more than 128 versions) |
| A `.nupkg` | one GET of its catalog leaf and one of the file, the first time; then the verified cache |
| A search | one GET to the search service, plus a snapshot for each result that isn't cached |
| Vulnerability data | the index and its files, once per metadata TTL |

## Limitations

- **The NU1603 upgrade** described under One snapshot per package, unless the build fails on that warning.
- **Unlisted versions are held for the full delay on a fresh instance.**
- **Not served:** the `.nuspec`, icons, readmes, the catalog, autocomplete, symbol packages, publishing (`dotnet nuget
  push` needs nuget.org), and the SemVer 1 registration hives. Clients older than NuGet 4.3, which don't know
  `RegistrationsBaseUrl/3.6.0`, find no registration resource.
- **Private feeds** stay direct sources, mapped with `packageSourceMapping`. `/nuget/<id>/` is kept free for them.
- **A package deleted and published again** under the same version shows as tampering until an operator clears it.

## Code and tests

- `src/slowshield/ecosystems/nuget/version.py`: NuGet version parsing, normalization and order.
- `src/slowshield/ecosystems/nuget/registration.py`: snapshots, page recomputation, URL rewriting.
- `src/slowshield/ecosystems/nuget/service.py`: routes, the service index, publish times, policy, downloads, search,
  vulnerability data.
- `tests/unit/test_nuget.py`, `tests/integration/test_nuget.py` (fake registration, catalog, flat container and search
  in `fakeupstream/`), `tests/e2e/test_stack.py::test_nuget_restores_through_the_proxy` (real `dotnet restore`, not
  run yet).
