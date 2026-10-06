# slowshield.org

The public website: a static site in `src/`, built by `build.py` and served by Cloudflare Workers static assets
(Free plan, no Worker script). The response headers, including the CSP, live in `_headers`.

| File | Purpose |
|---|---|
| `build.py` | Builds `src/` into `dist/site`, fingerprints CSS/JS, copies brand assets and `_headers`, and fails on CSP violations, broken links or anchors, a weakened `_headers` or Cloudflare limits |
| `_headers` | Security headers on every response, and Cache-Control per path |
| `wrangler.jsonc` | Production Worker `slowshield-website` (custom domain `slowshield.org`) |
| `wrangler.preview.jsonc` | Separate Worker `slowshield-website-preview` for per-PR previews |
| `dns/*.zone` | Target DNS records of `slowshield.org` and the redirect zones `slowshield.net`, `slowshield.com` |
| `package.json`, `package-lock.json` | Pinned Wrangler, locked against registry.npmjs.org. `overrides` lifts `sharp` (via miniflare) to `^0.35.5` for GHSA-wq5f-xc86-pv6w; drop it once Wrangler's miniflare requires 0.35.5 or later |
| `../.github/workflows/website.yml` | Build on every PR, preview for same-repository PRs, deploy on push to `main` |

## Work on it locally

```sh
UV_INDEX_URL= uv run --no-project python website/build.py --out dist/site
cd website && npm ci --ignore-scripts && npx wrangler dev -c wrangler.jsonc --ip 127.0.0.1 --port 18091
```

`wrangler dev` runs the same asset handling as production, `_headers` included. Rebuild after each change.

## Deployments

- **Pull requests** build and validate the site. Same-repository PRs also get a Worker Preview on workers.dev
  (linked as "View deployment" on the PR, never indexed), deleted when the PR closes. Fork PRs only build: no
  secrets, no preview.
- **Push to `main`** deploys `slowshield.org`, then checks that the new CSS is live, that all security headers
  are present, that fingerprinted assets are immutable and that a missing page returns 404.
- **Rollback**: revert the commit on `main`, or run `npx wrangler rollback -c wrangler.jsonc` (also in the
  dashboard under Deployments).

## One-time setup

### 1. Cloudflare account

1. Use an organisation-owned account with 2FA and at least two admins. The Free plan is enough.
2. Under Workers & Pages, register the account's `workers.dev` subdomain. Previews are served at
   `pr-<n>-slowshield-website-preview.<subdomain>.workers.dev`.

### 2. DNS: move the zones from Gandi to Cloudflare

`slowshield.org` is the canonical host; `slowshield.net` and `slowshield.com` only redirect to it. The target
records of each zone are in [`dns/`](dns/), in the format Cloudflare's own export uses.

1. Add `slowshield.org`, `slowshield.net` and `slowshield.com` (Full setup, Free plan).
2. Delete every record Cloudflare's scan imported from Gandi: the parking records (apex `A 217.70.184.38`,
   `www CNAME webredir.vip.gandi.net`) and Gandi's mail (`MX spool.mail.gandi.net` / `fb.mail.gandi.net`,
   `TXT "v=spf1 include:_mailcust.gandi.net ?all"`). A record left on the `slowshield.org` apex blocks the
   Worker custom domain.
3. DNS > Records > Import and Export: import `dns/<zone>.zone` into each zone with **Proxy imported DNS
   records** on. None of the domains sends or receives mail, and the files make receivers reject anything
   that claims otherwise, on every name: null `MX 0 .` and `v=spf1 -all` on the apex, `www` and a wildcard,
   every DKIM key revoked (`*._domainkey` with an empty `p=`), and DMARC `p=reject; sp=reject` with strict
   alignment. Do not add mail records to these zones.
4. At Gandi, switch each domain to the two Cloudflare nameservers and wait until the zone is **Active**.
5. SSL/TLS > Edge Certificates, per zone: **Always Use HTTPS** on, minimum TLS 1.2. Leave the zone HSTS
   setting off; HSTS comes from `_headers`.
6. DNS > Settings: enable DNSSEC and add the DS record at Gandi.

### 3. First deploy, from a laptop

Creating a Worker needs admin rights; the CI tokens only get Editor on one Worker each.

```sh
UV_INDEX_URL= uv run --no-project python website/build.py --out dist/site
cd website && npm ci --ignore-scripts
npx wrangler login
npx wrangler deploy -c wrangler.jsonc            # creates slowshield-website
npx wrangler deploy -c wrangler.preview.jsonc    # creates slowshield-website-preview (no public URL)
```

Attach the domain: Workers & Pages > `slowshield-website` > Settings > Domains & Routes > Add > Custom domain >
`slowshield.org`. Cloudflare creates the DNS record and the certificate. Check:

```sh
curl -sI https://slowshield.org/ | grep -iE 'content-security-policy|strict-transport|cache-control'
curl -s -o /dev/null -w '%{http_code}\n' https://slowshield.org/nope   # 404
```

### 4. Redirects to the canonical host

One Redirect Rule per zone (Rules > Redirect Rules), each a 308 with the query string kept and the target
`concat("https://slowshield.org", http.request.uri.path)`:

| Zone | When incoming requests match |
|---|---|
| `slowshield.org` | `(http.host eq "www.slowshield.org")` |
| `slowshield.net` | `(http.host in {"slowshield.net" "www.slowshield.net"})` |
| `slowshield.com` | `(http.host in {"slowshield.com" "www.slowshield.com"})` |

### 5. API tokens (Manage Account > Account API Tokens, account-owned)

| Token | Scope | Role | GitHub environment |
|---|---|---|---|
| `github-website-production` | Specified Workers: `slowshield-website` | Editor | `production` |
| `github-website-preview` | Specified Workers: `slowshield-website-preview` | Editor | `preview` |

Neither needs zone permissions, because the custom domain is attached in the dashboard. Give both an expiry
date. If a per-Worker token turns out not to be allowed to create Previews, fall back to **Account > Workers
Scripts: Edit** for the preview token.

### 6. GitHub (Settings of squirro/slowshield)

1. Actions variable `CLOUDFLARE_ACCOUNT_ID` (not secret).
2. Environment `production`: deployment branches *Selected* → `main` only; secret
   `CLOUDFLARE_API_TOKEN` = production token.
3. Environment `preview`: no branch restriction (PR branches use it); secret `CLOUDFLARE_API_TOKEN` = preview
   token, and nothing else: every same-repository branch can reach it.
4. Before the repository goes public: Actions > General > Fork pull request workflows → "Require approval for
   all external contributors".

### 7. Verify

1. Open a PR that touches `website/`: the preview link appears on the PR, and `curl -sI <url>` shows
   `x-robots-tag: noindex` and the security headers. Closing the PR deletes the preview.
2. Merge: the deploy job runs its smoke test against https://slowshield.org.

Worker Previews are in open beta. If a preview URL answers with error 1042
(https://github.com/cloudflare/workers-sdk/issues/15890), make sure the preview Worker was deployed once
(step 3), or use `wrangler versions upload --preview-alias pr-<n>` instead.
