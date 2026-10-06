# Maven and Java

Status: implemented (https://github.com/squirro/slowshield/issues/18, proposal in
[this comment](https://github.com/squirro/slowshield/issues/18#issuecomment-5993827803)). The design follows
[go.md](go.md) where it can. It was reviewed against Maven 3.9.16 and Gradle 8.14.5 / 9.8.0 on 2026-10-05. The
implementation was then run with real Maven 3.9 and Gradle 8 and 9 builds against Maven Central, Google Maven and
the Plugin Portal: every one of 297 downloaded files was verified, and a 3-day-old pin failed with
`425 Too Early`. sbt, Coursier, Maven 4 and a Nexus in front are not verified yet.

SlowShield serves Maven repositories at `/maven/`, for Maven, Gradle, sbt, Coursier and Bazel. Versions younger than
the delay are held back, known malware is refused, and every file is checked against the repository's checksums and
the fingerprint recorded on its first download.

## Repositories and paths

| Path | Upstream | For |
|---|---|---|
| `/maven/all/` | Google's groups (from its `master-index.xml`) go to Google Maven, everything else to Maven Central | Maven `settings.xml` with `<mirrorOf>*</mirrorOf>`, sbt, Coursier |
| `/maven/central/` | `repo1.maven.org/maven2` | Gradle `mavenCentral()`, Bazel |
| `/maven/google/` | `dl.google.com/dl/android/maven2` | Gradle `google()` |
| `/maven/gradle-plugins/` | `plugins.gradle.org/m2` | Gradle `gradlePluginPortal()` and plugin resolution |
| `/maven/<id>/` | a repository the operator configures | anything else (JitPack, Confluent, …) |

The rest of the path is the standard Maven layout.

- **Why `/maven/all/` comes first.** Maven sends every repository of a build through one mirror. `<mirrorOf>google</mirrorOf>`
  doesn't match a Google repository a project declares under another id, and a mirror pointing at Central alone turns
  every Google artifact into a 404, which Maven then caches for a day.
- **The Plugin Portal also serves Central.** It answers any Central path with a 303 to `repo.maven.apache.org`.
  SlowShield follows redirects only to the hosts in that repository's `download_hosts`.
- **One namespace.** Publish times, exceptions and blocklist entries belong to the artifact (`groupId:artifactId`
  and version), whichever repository path served it. An exception can't open Central through the Plugin Portal.

## What clients see

| Request | Behaviour |
|---|---|
| `<g>/<a>/maven-metadata.xml` | Versions too new or blocked are removed, `<latest>` and `<release>` recomputed, `<lastUpdated>` kept. `.sha1`, `.md5`, `.sha256` and `.sha512` are computed from this body, and `X-Checksum-Sha1`/`-MD5` are sent. Version ranges, `LATEST`/`RELEASE` and Gradle's `1.+` and `latest.release` then pick the newest allowed version |
| any file of a version (`.pom`, `.jar`, `.module`, `.aar`, `-sources.jar`, `.asc`, …) | `425 Too Early` with `Retry-After` when too new, `451` when blocked or tampered, else verified and cached. `HEAD` is gated the same way |
| a checksum file of a version's file | Gated like that file; from the verified download when SlowShield has one, else from upstream (cached) |
| group-level metadata (plugin prefixes), archetype catalogs | Passed through unchanged |
| metadata SlowShield can't filter (unreadable, a `DOCTYPE`, tags its edits can't see) | `503`: never passed on with held or blocked versions in it |
| `.index/` (Central's multi-gigabyte search index), `-SNAPSHOT` on a built-in repository | `404` |

**Why 425.** Maven and Gradle show only the status line of an error, never its body:

```
Could not transfer artifact org.example:lib:jar:1.4.0 from/to slowshield (https://slowshield.example.com/maven/all/):
  status code: 425, reason phrase: Too Early (425)
> Could not GET '…/lib-1.4.0.pom'. Received status code 425 from server: Too Early
```

`403 Forbidden` reads like a credentials problem. A custom reason phrase can't reach clients either: Caddy writes the
standard one, and HTTP/2 has none. Maven 3.9 re-requests a 425 on every build (like a 403, unlike a 404, which it
caches until the update interval or `-U`), and Gradle re-requests both. Once the hold ends, the next build works.

Upstream failures are `503`, never `404`: Maven caches a `404`.

## Publish time

A file's publish time is its `Last-Modified` on the repository: when the repository stored it. A version's publish
time is its `.pom`'s.

| Checked 2026-10-05 | `Last-Modified` |
|---|---|
| Central, commons-lang3 3.21.0 `.pom` | 2026-09-25 20:01:05, the time Central's directory listing shows |
| Central, the other files of that version | written over the next 11 seconds (`.jar` :06, `-sources.jar` :12, `.pom.asc` :16) |
| Central, commons-lang3 `maven-metadata.xml` | 2026-09-29: rewritten later, so `<lastUpdated>` is not a publish time |
| Central, junit 3.8.1 `.pom` (released 2002) | 2007: older files carry a later date, which only holds them longer |
| Google, androidx core 1.13.1 `.pom` | 2024-05-01 (all files of a version share one time) |
| Google, appcompat-v7 28.0.0 `.pom` (released 2018) | 2019-09-21: rewritten in bulk |

The rules:

1. **Metadata.** Versions are judged newest first, in Maven's version order, until one is old enough, with a
   `HEAD` of its `.pom` for a version SlowShield hasn't seen (at most 20 per evaluation; the rest are held until a
   later evaluation, at most five minutes on, has looked them up). The result is stored once.
2. **Files.** Each file is judged by its own `Last-Modified`, from the download SlowShield makes anyway: a file added
   to an old version later is held on its own. A version already known to be too new is refused before any request.
   A cached file is judged again by its version's `.pom` date, so it is held again when the policy gets stricter; if
   that date can't be looked up (an outage), the first-listed time can still clear it, otherwise the answer is `503`.
3. **Only a `200` counts.** Central's 404s carry a `Last-Modified` too. Without a plausible value, the clock starts
   when SlowShield first sees the file.
4. **A second clock.** SlowShield records when it first saw a version listed in the upstream metadata. A version (and
   its files) is old enough if either clock says so, so a repository that rewrites its files in bulk, as Google did,
   doesn't hold everything back on a long-running instance. A version is only listed once it is published, so this
   clock can't age anything in advance.

## Policy

- **Per version, like npm and Go,** with the same delay and exceptions (`ecosystem = "maven"`, `package =
  "groupId:artifactId"`).
- **No fail-open by default.** `upstreams.maven.fail_open = false`: an artifact with no version old enough is held
  too. On Maven, brand-new artifacts are the realistic attack (typosquats, dependency confusion), and builds pin
  exact versions, so there is no older version to fall back to anyway.
- **Pins are refused, not downgraded.** Most builds pin exact versions, so the protection is the `425` for a pin that
  is too new. Renovate `minimumReleaseAge` and Dependabot `cooldown` (both support Maven and Gradle) keep pins from
  getting ahead of the delay.

## Integrity

| Repository | Registry digest |
|---|---|
| Central | `x-checksum-sha1` on the response, checked while streaming: no extra request |
| Google, operator repositories | the file's `.sha1`, fetched once and cached |
| Plugin Portal | the sha256 in the path it redirects to (`plugins-artifacts.gradle.org/…/<sha256>/<file>`) |

- **Fingerprints and headers.** Every file is fingerprinted on first download (released Maven files never change), and
  responses carry `X-Checksum-Sha1`, so Maven doesn't request checksum files. Gradle never does.
- **Signatures.** `.asc` files are passed through. Verifying PGP signatures is a later, opt-in feature: the hard part
  is trusting the keys.

## Malware feeds

OSV `Maven` and GitHub `maven`; packages are named `groupId:artifactId`. Versions follow Maven's `ComparableVersion`
order (ported, with Maven's own test cases), which also orders the metadata walk. Exact matches use it too: an
advisory for `1.0` also blocks `1.0.0` and `1-ga`, which Maven treats as the same version.

## Client setup

| Tool | Setup |
|---|---|
| Maven | `~/.m2/settings.xml`: `<mirror><id>slowshield</id><mirrorOf>*</mirrorOf><url>https://HOST/maven/all/</url></mirror>`; add `,!internal` for private repositories |
| Gradle | an init script in `~/.gradle/init.d/` that points `mavenCentral()`, `google()` and the Plugin Portal at SlowShield, in `beforeSettings` (plugin resolution), `settingsEvaluated` (`dependencyResolutionManagement`) and `allprojects` (`buildscript` and project repositories) |
| sbt | `~/.sbt/repositories` with `-Dsbt.override.build.repos=true` |
| Coursier | `COURSIER_REPOSITORIES` |
| Bazel | `--downloader_config` rewriting `repo1.maven.org`, `repo.maven.apache.org` and `dl.google.com` |

Private repositories stay out of SlowShield (`!internal` in `mirrorOf`). SlowShield must face the clients directly:
behind a Nexus or Artifactory, its `425` becomes that proxy's cached `404`.

## Upstream load

| | Requests |
|---|---|
| Startup, background | none |
| Google's `master-index.xml` | one a day, once someone uses `/maven/all/` |
| A new version in a metadata walk | one `HEAD` of its `.pom` |
| A file | the client's own `GET`; for Google and operator repositories plus its `.sha1` (which Maven then doesn't request) |

## Limitations and follow-ups

- Snapshots are served for operator repositories only, without a release-age check (they change by design). Only
  the version makes a file a snapshot's: an artifactId ending in `-SNAPSHOT` doesn't.
- Ivy-layout repositories (older sbt plugins) aren't supported yet.
- PGP signature verification, opt-in.
