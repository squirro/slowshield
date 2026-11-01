# UI sign-in

SlowShield's UI can let people sign in with their company identity over OpenID Connect. Each person gets a role from
the identity provider (IdP):

| Role | Who | Can |
|---|---|---|
| Viewer | anyone not signed in (unless sign-in is required), and anyone signed in that no rule maps | read the UI |
| User | mapped by an IdP claim or a verified email | everything a Viewer can, plus User actions (none yet) |
| Admin | mapped by an IdP claim or a verified email | everything a User can, plus the Users and Activity pages, disabling users, and confirming a shield wall leader |

**Nothing changes by default.** Without `SLOWSHIELD_AUTH`, the UI is public and read-only, as before. **The package
proxy never needs a sign-in**, whatever is set here: every ecosystem path, `/v2`, `/.well-known`, `/healthz`,
`/readyz` and `/_shieldwall` stay open.

SlowShield uses only what Keycloak, Okta, Entra ID and Google Workspace all support. It finds the rest through
discovery and uses it where the IdP offers it: pushed authorization requests (PAR), the `iss` in the sign-in response
(RFC 9207), and signing out at the IdP. **Only Keycloak is tested end to end.** The other IdPs below are documented
but not fully tested.

## How it works

- **Sign-in.** SlowShield uses Authorization Code with PKCE (S256), `state` and `nonce`, as a confidential client.
  - It authenticates to the IdP with `private_key_jwt` (a key file) or `client_secret_basic` (a secret file).
  - It sends the request through PAR when the IdP has it. `SLOWSHIELD_OIDC_PAR=required` refuses to sign in without
    PAR.
- **The ID token.** Its signature is checked against the IdP's JWKS: RS256, PS256 or ES256 only, so `none` and HMAC
  are refused. SlowShield also checks `iss`, `aud`, `azp`, `exp`, `iat` and `nonce`.
  - A person is identified by the issuer and `sub`, never by email.
  - Claims the ID token leaves out come from the userinfo endpoint.
- **Sessions.** Sessions live in SlowShield's database. The browser holds only a random ID in
  `__Host-slowshield_session` (`Secure; HttpOnly; SameSite=Lax`), and every sign-in gets a new ID.
  - A session lasts `SLOWSHIELD_SESSION_HOURS` (12) at most.
  - Every `SLOWSHIELD_SESSION_RECHECK_MINUTES` (15), the next page load goes back to the IdP silently
    (`prompt=none`). While the IdP session lives, the person doesn't notice and their role is updated.
  - If the IdP ended its session (sign-out, a disabled account), SlowShield ends its own. This works with every IdP
    and needs no connection from the IdP to SlowShield.
- **Sign-in state.** While a sign-in is under way, its state is kept in a short-lived cookie
  (`__Host-slowshield_login`, 10 minutes). Any node or worker can finish a sign-in that another one started.
- **Requiring sign-in.** With `SLOWSHIELD_UI_REQUIRE_LOGIN=true`, anyone not signed in goes straight to the IdP and
  comes back to the page they asked for. There is no sign-in page in between.
  - If the IdP can't be reached, the UI shows "Sign-in unavailable", and the proxy is unaffected.
  - A recheck that can't reach the IdP keeps the session and tries again a minute later.
- **Signing out.** Signing out ends the SlowShield session, and also the IdP session when the IdP has an
  `end_session_endpoint`. Front-channel logout isn't supported: it needs third-party cookies in the IdP's iframe.

### Roles

Rules apply in this order:

1. An admin rule that matches makes an Admin.
2. Otherwise, a user rule that matches makes a User.
3. Otherwise, the person gets `SLOWSHIELD_AUTH_DEFAULT_ROLE` (`viewer`).

The IdP decides roles. SlowShield works them out again at every sign-in and recheck, and the UI can't change them.

There are two kinds of rules:

- **A claim.** `SLOWSHIELD_OIDC_ROLES_CLAIM` names a list-valued claim (`groups`, `roles`, `slowshield_roles`, or a
  dotted path such as `realm_access.roles`). Its values are matched exactly against `SLOWSHIELD_OIDC_ADMIN_VALUES` and
  `SLOWSHIELD_OIDC_USER_VALUES`.
- **Email lists.** `SLOWSHIELD_AUTH_ADMIN_EMAILS` and `SLOWSHIELD_AUTH_USER_EMAILS` take exact addresses or
  `*@domain`. They count only when the IdP says the email is verified (`email_verified: true`). They also serve for
  bootstrap and break-glass access.

SlowShield stores only the claim values or the email rule that gave the role (shown as "Because" on the Users page),
never the person's full group list.

`SLOWSHIELD_OIDC_REQUIRE_CLAIMS` refuses anyone whose claims don't match, e.g. `hd=example.com` (a Google Workspace
domain) or `tid=<tenant id>` (Entra ID).

## Configuration

```sh
SLOWSHIELD_AUTH=oidc
SLOWSHIELD_UI_REQUIRE_LOGIN=true                     # optional: no UI without signing in
SLOWSHIELD_UI_URLS=https://slowshield.example.com    # every URL the UI is reached at, comma-separated
SLOWSHIELD_OIDC_ISSUER=https://idp.example.com/realms/example
SLOWSHIELD_OIDC_CLIENT_ID=slowshield
SLOWSHIELD_OIDC_CLIENT_KEY_FILE=/run/secrets/oidc_client   # or SLOWSHIELD_OIDC_CLIENT_SECRET_FILE
SLOWSHIELD_OIDC_PAR=required                         # where the IdP has PAR (Keycloak, Okta)
SLOWSHIELD_OIDC_ROLES_CLAIM=slowshield_roles
SLOWSHIELD_OIDC_ADMIN_VALUES=SlowShield Admins
SLOWSHIELD_OIDC_USER_VALUES=SlowShield Users
```

Lists are comma-separated and trimmed, so values with spaces and dashes work as they are. Every setting also has a
key in `[auth]` and `[auth.oidc]` of `config.toml` ([configuration.md](configuration.md), `config.example.toml`). A
restart applies changes.

The start fails on a configuration that can't work. That includes:

- `http` UI URLs (the session cookies are `Secure`; locally, use `https://localhost`);
- an Entra ID issuer for `/common` or `/organizations`;
- both a key file and a secret file, or neither;
- role values without a roles claim;
- a key file that can't be read.

The IdP itself doesn't have to be reachable at start.

### The client key (`private_key_jwt`)

A key is better than a client secret: SlowShield proves it holds the key with a short-lived signed assertion, and
nothing reusable is ever sent. Create the key and print the certificate to register at the IdP:

```sh
slowshield auth client-cert --new ec --key oidc-client.pem > slowshield-oidc.crt    # EC P-256, ES256
slowshield auth client-cert --new rsa --key oidc-client.pem > slowshield-oidc.crt   # RSA 3072, RS256 (Entra ID)
```

Then mount `oidc-client.pem` as a secret (Helm `auth.oidc.clientKeySecret`, Compose `OIDC_CLIENT_SECRET_FILE`, Podman
`slowshield.container.d/oidc-client.conf.example`) and point `SLOWSHIELD_OIDC_CLIENT_KEY_FILE` at it. `--jwk` prints
a JWKS instead of a certificate. The assertion's `kid` is the key's RFC 7638 thumbprint, which is what Keycloak
derives from an imported certificate.

### Several hostnames

The UI can be reached under more than one name, e.g. `https://slowshield.example.com` and
`https://slowshield.<tailnet>.ts.net`. List every one in `SLOWSHIELD_UI_URLS`, and register both URIs below at the IdP
for each of them:

- `https://<host>/ui/auth/callback`: the redirect URI;
- `https://<host>/ui/auth/signed-out`: the post-logout redirect URI.

The redirect URI is always the listed URL whose host matches the request; it's never built from the `Host` header. A
host that isn't listed gets a 421. Each name has its own session, because `__Host-` cookies belong to one host.

### Shield wall

Every leader and follower is a complete SlowShield with its own users and sessions, so each node configures sign-in
itself.

- The leader doesn't push auth settings, just as it doesn't push upstreams or privacy settings.
- All nodes that share a hostname must use the same client and the same key or secret.
- A sign-in can start on one node and finish on another (the state is in the browser's cookie).
- A node that has no session for a browser sends it to the IdP without a prompt, and the live IdP session brings it
  straight back.
- With sign-in on, only an Admin can confirm a follower's leader on its Shield wall page. The page shows who did.

## Keycloak (tested)

This sets up a hardened client for SlowShield in Keycloak 26. Replace `slowshield.example.com` with each of your UI
URLs.

1. **Realm settings → General:** set *Require SSL* to *all requests*. If Keycloak is reached under several names, set
   the realm's *Frontend URL*, so the issuer is always the same.
2. **Realm roles:** create the roles SlowShield maps, e.g. `SlowShield Admins` and `SlowShield Users`, and assign them
   to people or groups. Anyone else in the realm who signs in becomes a Viewer.
3. **Clients → Create client:**
   - *Client type* `OpenID Connect`, *Client ID* `slowshield`.
   - *Capability config*:
     - turn *Client authentication* on, and *Authorization* off;
     - in *Authentication flow*, keep *Standard flow* only: turn *Direct access grants*, *Implicit flow*, *Service
       accounts*, *OAuth 2.0 Device Authorization Grant*, *OIDC CIBA Grant* and *Standard Token Exchange* off;
     - set *PKCE Method* to `S256`.
   - *Login settings*:
     - *Valid redirect URIs*: `https://slowshield.example.com/ui/auth/callback`, one exact URI per UI URL, with no
       wildcards;
     - *Valid post logout redirect URIs*: `https://slowshield.example.com/ui/auth/signed-out`;
     - *Web origins*: empty (SlowShield needs no CORS);
     - *Home URL*: `https://slowshield.example.com/ui/`.
4. **Credentials:** pick a *Client Authenticator*.
   - **Signed JWT** (recommended), with *Signature algorithm* `ES256` (or `RS256` for an RSA key). Then go to
     **Keys**: turn *Use JWKS URL* off, *Import key* → *Certificate PEM*, and upload `slowshield-oidc.crt` from
     `slowshield auth client-cert`.
   - Or **Client Id and Secret**, and put the secret in the file `SLOWSHIELD_OIDC_CLIENT_SECRET_FILE` names.
5. **Advanced** tab:
   - *Pushed authorization request required*: on. Then set `SLOWSHIELD_OIDC_PAR=required` in SlowShield.
   - *Exclude Issuer From Authentication Response*: off. SlowShield then checks the `iss` Keycloak returns (RFC 9207).
   - *Use refresh tokens*: off. SlowShield doesn't use them.
   - *Front channel logout*: off. Leave the backchannel logout URL empty.
   - *Access Token Lifespan*: short, e.g. 5 minutes. SlowShield uses the access token only once, for userinfo.
   - *Consent required* (Settings tab): off.
6. **Client scopes:**
   - Keep `basic`, `email` and `profile`.
   - Remove `roles`, `web-origins`, `acr`, `address`, `phone`, `offline_access`, `microprofile-jwt` and
     `organization`. SlowShield needs none of them, and they would put more about the person into its tokens.
7. **Client scopes → slowshield-dedicated:**
   - **Mappers → By configuration → User Realm Role**: *Token Claim Name* `slowshield_roles`, *Multivalued* on, *Add
     to ID token* on, *Add to access token* off, *Add to userinfo* on, *Add to token introspection* off.
   - **Scope:** turn *Full scope allowed* off, then assign only the realm roles SlowShield maps. The token then carries
     those roles and nothing else.
   - With groups instead of roles, use a *Group Membership* mapper (*Full group path* off) into `slowshield_roles`.
8. **SlowShield:** set the variables under [Configuration](#configuration), with the issuer
   `https://<keycloak>/realms/<realm>`.

Keycloak's sessions and token lifespans don't need changing. SlowShield checks the Keycloak session again every 15
minutes, and SSO Session Idle (30 minutes by default) is longer than that.

To keep everyone else out of SlowShield entirely, rather than letting them in as Viewers, restrict the client in
Keycloak, e.g. with an authentication flow that requires a role. You can also give SlowShield
`SLOWSHIELD_OIDC_REQUIRE_CLAIMS` for a claim only allowed people carry.

## Okta (documented, not fully tested)

- Create an *OIDC Web Application* with the *Authorization Code* grant only, and *Require PKCE*.
  - Sign-in redirect URIs: `https://<host>/ui/auth/callback`.
  - Sign-out redirect URIs: `https://<host>/ui/auth/signed-out`.
  - Assign the app to the groups that may sign in.
- Client authentication: *Public key / Private key*, with the JWKS from `slowshield auth client-cert --jwk`. A client
  secret works too.
- *Require PAR*: on, and `SLOWSHIELD_OIDC_PAR=required`.
- Roles:
  - Add a *groups* claim with a filter (e.g. *starts with* `SlowShield-`) to the ID token;
  - set `SLOWSHIELD_OIDC_ROLES_CLAIM=groups`.
  - With the org authorization server, groups may come from userinfo only; SlowShield fetches them there.
- Issuer: `https://<org>.okta.com` (org authorization server) or `https://<org>.okta.com/oauth2/<server id>`.

## Microsoft Entra ID (documented, not fully tested)

- Register an app: *Accounts in this organizational directory only*.
  - Redirect URI (Web): `https://<host>/ui/auth/callback`.
  - Front-channel logout URL: empty.
- Credentials:
  - Upload the certificate from `slowshield auth client-cert --new rsa` under *Certificates*. Entra ID asks for the
    certificate's thumbprint in the assertion, so append `slowshield-oidc.crt` to the key file:
    `cat oidc-client.pem slowshield-oidc.crt > oidc-client-with-cert.pem`.
  - A client secret works too.
- Roles:
  - Define **app roles** (e.g. `SlowShield.Admin`, `SlowShield.User`) and assign people to them. Assigning groups to
    app roles needs Entra ID P1.
  - Set `SLOWSHIELD_OIDC_ROLES_CLAIM=roles`.
  - Avoid the `groups` claim: past 200 groups Entra ID leaves it out (overage), and SlowShield then gives the default
    role and logs a warning.
- **Email lists never apply:** Entra ID sends no `email_verified`.
- Issuer: `https://login.microsoftonline.com/<tenant id>/v2.0`. `/common` and `/organizations` are refused.
- To keep out guests of other tenants, set `SLOWSHIELD_OIDC_REQUIRE_CLAIMS=tid=<tenant id>`.
- Entra ID has no PAR: leave `SLOWSHIELD_OIDC_PAR=auto`.

## Google Workspace (documented, not fully tested)

- Create an *OAuth client ID*, type *Web application*, on an **Internal** consent screen.
  - Redirect URI: `https://<host>/ui/auth/callback`.
  - Google only offers a client secret.
- Google sends no groups. Use the verified-email lists (`SLOWSHIELD_AUTH_ADMIN_EMAILS`, `SLOWSHIELD_AUTH_USER_EMAILS`)
  and `SLOWSHIELD_OIDC_REQUIRE_CLAIMS=hd=example.com`. Group-based roles come with SAML.
- Google has no PAR and no end-session endpoint. Signing out ends the SlowShield session only.
- Issuer: `https://accounts.google.com`.

## Authentik (documented, not fully tested)

- Create an *OAuth2/OpenID Provider*:
  - *Client type* confidential;
  - redirect URI `https://<host>/ui/auth/callback` (strict);
  - signing key set.
- Add a *Scope mapping* that returns `{"slowshield_roles": [group.name for group in request.user.ak_groups.all()]}`,
  or use the built-in `groups` claim.
- Issuer: `https://<authentik>/application/o/<slug>/`, with the trailing slash, exactly as discovery names it.

## Pages, records and commands

- **The header** shows who is signed in, their role, and *Sign in* / *Sign out*.
- **Users** (`/ui/users`, Admins only) lists everyone who signed in to this instance:
  - their name, email and role, and the claim value or email rule that gave it;
  - their first and last sign-in, and their open sessions.
  
  Admins can disable a user here. Their sessions end at once, and they can't sign in to this instance until enabled
  again.
- **Activity** (`/ui/activity`, Admins only, CSV export) records sign-ins, refused sign-ins with the reason,
  sign-outs, sessions the IdP ended, role changes, and what Admins changed.
  - Entries are kept for `event_retention_days`.
  - Client IPs follow `record_client_ip` and `client_ip_retention_days`, as on security events.
- **Metrics:** `slowshield_auth_logins_total{result}`, `slowshield_auth_rechecks_total{result}` and
  `slowshield_auth_sessions_active` ([observability/METRICS.md](../observability/METRICS.md)).
- **On the command line**, run next to the server (`docker compose exec slowshield …`):
  - `slowshield users list`;
  - `slowshield users disable <id>` and `slowshield users enable <id>`;
  - `slowshield users logout-all`, which ends every session.

**Break-glass.** If the IdP's role mapping breaks, an address in `SLOWSHIELD_AUTH_ADMIN_EMAILS` still makes an Admin,
as long as the IdP says the address is verified. If the IdP itself is down, the UI is unavailable with
`SLOWSHIELD_UI_REQUIRE_LOGIN=true`, and read-only for everyone without it. The proxy keeps serving either way.

## Not yet

- SAML 2.0.
- Tailscale identity, for sign-in and for tagging downloads with a device and person (blocked on tailscale-py).
- Back-channel logout.
- Users and the activity log of followers on the leader's pages.
- GitHub sign-in.

Tracked in [#64](https://github.com/squirro/slowshield/issues/64).
