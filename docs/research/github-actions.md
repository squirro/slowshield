# Shielding GitHub Actions

**Verdict:** yes — as a **policy gate**, not a byte proxy. GitHub resolves tag → SHA server-side and the runner
downloads a tarball by SHA without verifying it; hosted runners have no proxy hook, and a proxy on self-hosted
runners only sees `CONNECT codeload.github.com` without TLS interception.

## How actions are fetched

* "Set up job" sends every `uses:` ref to GitHub (`ResolveActionDownloadInfo`), receives `ResolvedSha` +
  tarball URL + token, unpacks into `_work/_actions` with no integrity check; composites recurse (max depth 9).
* Order on the runner: download → `ACTIONS_RUNNER_HOOK_JOB_STARTED` → container pull/build → `pre:` steps → steps.
  A failing job-started hook is a real pre-execution gate; a "first step" gate is not (Dockerfile builds and
  other actions' `pre:` already ran).
* `docker://image:tag` actions and Dockerfile actions are outside SHA pinning.

## What exists (Oct 2026)

* GitHub: org/enterprise **SHA-pin policy** and `!owner/repo@ref` blocking (Aug 2025; reusable workflows can still
  use tags); **immutable releases** (rarely used by actions; major tags like `v4` stay mutable); Dependabot
  `cooldown` for github-actions; `gh-actions-lock` in preview (no cooldown). **No minimum-age control.**
* Advisory DB `actions` ecosystem: 56 reviewed advisories, 0 `type=malware` → SlowShield's malware-only GitHub feed
  gets nothing here today. Advisory lag: tj-actions ~14 h, Trivy 5 days, reviewdog 8 days.
* Third parties: StepSecurity Harden-Runner, zizmor (`impostor-commit`, `ref-version-mismatch`), pinact
  `--min-age`, Socket, Scorecard.

## Proposed first feature: `slowshield actions check`

1. **Age = now − first_seen(repo, sha)** from a SlowShield ledger (poll `git ls-remote` for the action inventory).
   Commit dates are attacker-controlled (the malicious trivy commit claimed 2024-10-15).
2. **Anomaly checks** for SHAs seen before the ledger existed: commit older than its parent, not on the default
   branch, unsigned while the parent is signed (all three flag the trivy commit).
3. **Tag moves:** exact tags (`v1.2.3`) must never move; major tags may only fast-forward on the default branch
   and the new SHA must pass the age threshold.
4. **Blocklist:** GHSA/OSV `actions` advisories mapped onto ledger tags + local allow/deny lists.
5. **Coverage:** transitive composites, reusable workflows, `docker://` tags (warn).

Runs as an org-ruleset required check on PRs touching `.github/**` / `action.yml` (together with the SHA-pin
policy) and as `ACTIONS_RUNNER_HOOK_JOB_STARTED` on self-hosted runners; optionally emits an `actions.lock`.

Cannot catch: sleeper commits older than N days, runtime downloads (`curl | sh`, release binaries, images),
compromise of your own repos, tag moves after merge without SHA pinning, GitHub itself.

Complementary today: point package managers in steps at SlowShield (`PIP_INDEX_URL`, `UV_DEFAULT_INDEX`,
`npm_config_registry`, `YARN_NPM_REGISTRY_SERVER`) and block direct egress to the public registries.

Sources: actions/runner (ActionManager.cs, JobExtension.cs) · docs.github.com self-hosted proxies, job hooks ·
github.blog 2025-08-15 (SHA pinning policy), 2025-08-26 (immutable releases), 2026 Actions security roadmap ·
github/gh-actions-lock · GHSA-69fq-xp46-6x23 · wiz.io reviewdog · stepsecurity.io Trivy · docs.zizmor.sh · pinact.
