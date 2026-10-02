# Shielding editor extensions

**Verdict:** partly. A gallery-level release-age delay would have fully stopped the May 2026 GitHub breach;
a blocklist would not have (the advisory came 14 days later).

## Reference incidents

* **GitHub internal-repo breach via Nx Console 18.95.0 (TeamPCP, 18–20 May 2026).** A leaked contributor token
  published a malicious update of `nrwl.angular-console` (~2.2M installs). It was live ~18 min on the VS
  Marketplace and ~36 min on Open VSX, but auto-update activated it ~6,000 times. Opening a workspace ran
  `npx github:nrwl/nx#<orphan commit>`, a credential stealer + backdoor. A GitHub employee was hit; ~3,800 internal
  repositories were exfiltrated (GitHub: "directionally consistent"). OSV `MAL-2026-5161` appeared 2026-06-01.
* **s1ngularity / Nx (Aug 2025).** Malicious `nx` on npm for ~4 h; Nx Console installed `nx@latest` on editor
  start, so merely opening the editor ran it. Stolen secrets were pushed to public repos in victims' accounts.
  An npm delay would have stopped it if the extension's npm call honours the global `.npmrc` (likely, unverified).
* **GlassWorm (Oct 2025 → 2026, mostly Open VSX).** Self-spreading worm; "sleeper" extensions turned malicious
  ~5 days after publishing — a delay only partly helps, the blocklist matters.

## Mechanics

* VS Code Marketplace: `POST {serviceUrl}/extensionquery`, per-version `lastUpdated`, VSIX + signature assets on
  `*.gallerycdn.vsassets.io`; signatures verified when the gallery declares it → a proxy must pass bytes unchanged.
  Microsoft's `marketplace.json` lists malicious extension IDs.
* VS Code `extensions.autoUpdateDelay` (1.123+, policy `ExtensionsAutoUpdateDelay`) only covers auto-updates
  and exempts trusted publishers; `AllowedExtensions` pins exact versions; `ExtensionGalleryServiceUrl` (1.99+)
  redirects the gallery but is gated to eligible enterprise accounts.
* VSCodium: `VSCODE_GALLERY_*` env vars + `extensions.minReleaseAge`. Windsurf/Devin Desktop: plain setting
  `devin.marketplaceExtensionGalleryServiceURL`. Cursor: Open VSX via its own proxy, team controls
  `extensions.installCooldownHours`, custom gallery not supported. Open VSX API exposes `timestamp`, `sha256`,
  `signature`. JetBrains: `idea.plugins.host`, per-update `cdate`.
* Runtime downloads by extensions: child processes (npx, pip, go, language servers) use their own config/env —
  npm/PyPI traffic is covered today via global config; git specs (`npx github:…`) bypass registries
  (npm `allow-git=none`).

## Options (ranked)

1. **Policy/config pack + doctor CLI** — low effort, high value now.
2. **Gallery proxy upstream** (extensionquery + latest + asset passthrough, age filter, blocklist from
   `marketplace.json` and OSV `VSCode` ecosystems, sha256 check) — strongest; VSCodium, Windsurf, code-server,
   Theia directly; VS Code via enterprise policy; Open VSX as upstream for non-Microsoft editors.
3. **`AllowedExtensions` generator** (exact versions older than N days) — works with stock VS Code via MDM.
4. Forward proxy for runtime downloads — brittle, partial.
5. Client-side scanner of installed extensions — detection only.

Sources: GHSA-c9j4-9m59-847w (nx-console) · stepsecurity.io · helpnetsecurity.com 2026-05-20 · aikido.dev ·
api.osv.dev MAL-2026-5161 · code.visualstudio.com (v1_125, enterprise extensions, network) ·
microsoft/vsmarketplace private marketplace · VSCodium docs · cursor.com/help · docs.devin.ai · open-vsx.org API ·
plugins.jetbrains.com plugin signing · npm/cli allow-git.
