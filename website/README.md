# slowshield.net

The public website: a static site in `src/`, built by `build.py` and served by Cloudflare Workers static assets
(Free plan, no Worker script). The response headers, including the CSP, live in `_headers`.

| File | Purpose |
|---|---|
| `build.py` | Builds `src/` into `dist/site`, fingerprints CSS/JS, copies brand assets and `_headers`, and fails on CSP violations, broken links or anchors, a weakened `_headers` or Cloudflare limits |
| `_headers` | Security headers on every response, and Cache-Control per path |
| `wrangler.jsonc` | Production Worker `slowshield-website` (custom domain `slowshield.net`) |
| `wrangler.preview.jsonc` | Separate Worker `slowshield-website-preview` for per-PR previews |
| `package.json`, `package-lock.json` | Pinned Wrangler, locked against registry.npmjs.org |
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
- **Push to `main`** deploys `slowshield.net`, then checks that the new CSS is live, that all security headers
  are present, that fingerprinted assets are immutable and that a missing page returns 404.
- **Rollback**: revert the commit on `main`, or run `npx wrangler rollback -c wrangler.jsonc` (also in the
  dashboard under Deployments).

## One-time setup

### 1. Cloudflare account

1. Use an organisation-owned account with 2FA and at least two admins. The Free plan is enough.
2. Under Workers & Pages, register the account's `workers.dev` subdomain. Previews are served at
   `pr-<n>-slowshield-website-preview.<subdomain>.workers.dev`.

### 2. DNS: move the zones from Gandi to Cloudflare

1. Add `slowshield.net`, `slowshield.com` and `slowshield.org` (Full setup, Free plan).
2. Review the imported records:
   - Delete the Gandi parking records (apex `A 217.70.184.38`, `www CNAME webredir.vip.gandi.net`). A record
     left on the apex blocks the Worker custom domain.
   - Mail: keep the Gandi `MX` and `SPF` records only if Gandi mailboxes are used. Otherwise publish "no mail":
     `MX 0 .`, `TXT "v=spf1 -all"` and `_dmarc TXT "v=DMARC1; p=reject"`.
3. At Gandi, switch each domain to the two Cloudflare nameservers and wait until the zone is **Active**.
4. SSL/TLS > Edge Certificates, per zone: **Always Use HTTPS** on, minimum TLS 1.2. Leave the zone HSTS
   setting off; HSTS comes from `_headers`.
5. DNS > Settings: enable DNSSEC and add the DS record at Gandi.

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
`slowshield.net`. Cloudflare creates the DNS record and the certificate. Check:

```sh
curl -sI https://slowshield.net/ | grep -iE 'content-security-policy|strict-transport|cache-control'
curl -s -o /dev/null -w '%{http_code}\n' https://slowshield.net/nope   # 404
```

### 4. Redirects to the canonical host

- `www.slowshield.net`: a proxied `A www 192.0.2.1` record plus a Redirect Rule *Hostname equals
  www.slowshield.net* → `concat("https://slowshield.net", http.request.uri.path)`, 308, query string kept.
- `slowshield.com` and `slowshield.org`: in each zone, proxied `A @ 192.0.2.1` and `A www 192.0.2.1`, plus one
  Redirect Rule for both host names with the same target.

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
2. Merge: the deploy job runs its smoke test against https://slowshield.net.

Worker Previews are in open beta. If a preview URL answers with error 1042
(https://github.com/cloudflare/workers-sdk/issues/15890), make sure the preview Worker was deployed once
(step 3), or use `wrangler versions upload --preview-alias pr-<n>` instead.
