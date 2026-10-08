# Shield wall: one leader, many followers

Status: implemented (https://github.com/squirro/slowshield/issues/34). Pairing, reports up, policy, blocks, takedowns,
tamper flags and observations down, package files through the leader and the leader's per-instance views are in.
Tailscale auto-approval, inviting from the UI, and container images through the leader are not (see "Not yet").

Several SlowShield instances can stand together as a **shield wall**. One instance leads: it holds the policy, shows
every instance's traffic, and keeps a shared cache of package files. The others follow: they take the leader's
policy and blocks, report their statistics and events to it, and fetch package files through it. In a shield wall
each shield covers its neighbour, and the line holds as long as nobody breaks ranks; here, every instance keeps its
own shield up too. A follower is a complete SlowShield that works on its own whenever the leader can't be reached,
and catches up when it can.

## On one page

- **Hub and spoke, two tiers.** A leader is an ordinary instance with three extra jobs: the view over all instances,
  the source of policy, and a shared cache. It is never a follower. Followers never talk to each other.
- **Followers dial out; the leader never dials in.** One signed HTTPS exchange, long-polled for up to 25 seconds,
  carries reports up and changes down and is the heartbeat. Followers need no inbound port and work behind NAT.
- **Pairing like k3s.** `slowshield wall invite` on the leader prints a join string: the leader's URL, a hash
  of its Ed25519 key, and a single-use secret that expires after 10 minutes. The follower gets it in its environment,
  checks the leader's key against the hash, and its Shield wall page asks the operator to confirm the leader's
  fingerprint and click **Join** (`SLOWSHIELD_JOIN_CONFIRM=auto` skips the click for automated installs).
- **Ed25519 signatures on every message, not mTLS.** A small profile of RFC 9421 (HTTP Message Signatures) signs
  each request and each response, so authenticity survives Caddy, an ingress or Tailscale Serve terminating TLS in
  front of the app.
- **A small protocol of its own, not database replication.** Replication copies a database; a shield wall merges
  evidence under a trust policy, and lets instances on different versions sync.
- **Trust classes.** What tightens policy applies at once. What loosens it is bounded: a floor, a hold-down, and
  the *late-news rule* for observation times. Upstreams, caches and privacy settings never come from the leader.
- **Reports go up exactly once,** through an outbox written in the same transaction as the local statistics.
- **Evidence direct, bytes through the leader.** Indexes, publish times and tags come from the registry, as on any
  instance. Package files with a content address come through the leader, checked exactly as before.

## Roles

| Role | Set by | Does |
|---|---|---|
| standalone | the default; `SLOWSHIELD_SHIELDWALL_ROLE=standalone` | what SlowShield always did |
| leader | `SLOWSHIELD_SHIELDWALL_ROLE=leader` | serves `/_shieldwall/v1/` and `/.well-known/slowshield-shieldwall`; logs changes for followers; shows them |
| follower | a join string (`SLOWSHIELD_JOIN` or `SLOWSHIELD_JOIN_FILE`) | pairs, syncs, takes policy, fetches files through the leader |

**An instance keeps its role.** Each start records the role in the database (`meta`, `shieldwall_role`). A leader or
follower restarted without `SLOWSHIELD_SHIELDWALL_ROLE` (or with it empty, as Compose passes it) and without a join
string keeps the recorded role, and logs a warning that names it. `slowshield wall` reads the role the same way. Only
an explicit `SLOWSHIELD_SHIELDWALL_ROLE=standalone` (or `shieldwall.role = "standalone"` in the config file) takes an
instance out of the shield wall: a follower stops syncing (state `detached`) and drops its queued reports, and a
leader stops logging changes. A config reload keeps the role too; changing it takes a restart.

Each instance that isn't standalone has an Ed25519 key in `<data_dir>/shieldwall/identity.key` (mode 0600, created
on first start). Its ID is derived from the key. **Back up the leader's key:** losing it means pairing every follower
again. The sync runs on the worker that holds `leader.lock` (one per instance); every other worker reads what it
wrote every 5 seconds.

## Pairing

1. On the leader: `slowshield wall invite --name zurich-1 --location zurich` (in a container:
   `docker exec slowshield slowshield wall invite …`). It needs `public_url` (or `--url`): the URL followers
   reach the leader at. The token is stored with its secret; it works once, for 10 minutes (`--minutes`, up to 60).
2. The follower starts with `SLOWSHIELD_JOIN='ssj1:https://hq.example.com#<key hash>.<token>.<secret>'`.
3. It fetches `/.well-known/slowshield-shieldwall`, and refuses unless the key hashes to the value in the join string
   (and isn't its own). It pins the key.
4. Its Shield wall page, and a banner on every page, show the leader's name, URL and fingerprint, and a **Join**
   button. `slowshield wall invite` printed the same fingerprint on the leader.
5. On Join, the follower sends a signed `POST /_shieldwall/v1/join` with its public key, name, location, labels,
   and a proof: an HMAC of its key and the leader's ID under the token's secret. A copied request can't be replayed
   with another key. The leader checks the signature, the token (known, unused, not expired) and the proof, records
   the member, and burns the token.
6. In one transaction, the follower queues its history for the leader (below) and turns active; from then on every
   statistics flush also goes into the outbox.

**After a restart** the follower needs the join string only if it hasn't joined yet. A follower that has joined
syncs with the leader it stored (`shieldwall_leader.url` and the pinned key), with or without the join string, so a
used, expired join string can stay in its environment or go. One that was still waiting for the Join click, or
hadn't reached the leader yet, waits for the join string again: its Shield wall page and log say so. A new join
string for the same leader updates the stored URL.

**The UI can confirm, nothing else.** The UI has no login (docs/security.md), so the Join button can only confirm
the leader the operator configured: the leader comes from the environment, the form names the leader ID shown on
the page, and the request must come from the page itself (`Sec-Fetch-Site` and `Origin`, where the browser sends
them). There is no UI control to pick another leader, leave, or lower anything. Inviting stays in the CLI until the
UI has authentication.

**Removing a follower:** `slowshield wall remove zurich-1`. Its next sync gets a signed refusal; it then runs
on its own with its own config. Joining again takes a new join string. A follower that joins again replaces the
history the leader had for it. A removed follower restarted without a join string stays a follower in state
`removed`: it runs on its own as before, and its Shield wall page says it was removed.

**Leader key changed:** if the join string names another key than the pinned one, the follower stops syncing and
says so (state `key_changed`). Pairing again needs a fresh data directory, on purpose.

## Transport and authentication

Requests sign `@method`, `@path`, `@query` and `content-digest` (RFC 9530, sha-256); responses sign `@status`,
`content-digest` and the request's `Signature`, so a recorded response can't answer another request. Signatures
carry `created` and are refused beyond ±5 minutes; clocks are assumed to be NTP-synced. The leader looks the key up
by the signer's ID; a removed member gets a signed 403 with `"removed"`.

The traffic carries statistics, events and client IPs, so the leader's URL must be `https://`; join strings and
`invite` refuse plain `http://` except for `localhost`. A leader whose certificate a private CA signed (its Caddy's
internal CA, say) needs that CA on its followers, in `SLOWSHIELD_LEADER_CA_FILE`: Helm has
`shieldwall.leaderCaSecret`, Compose `LEADER_CA_SECRET_FILE` (`deploy/docker/secrets/README.md`), and `invite`
says so. A leader with an ACME certificate needs nothing. Request bodies are capped at 8 MB, read before the sender is
known; Caddy allows POST to `/_shieldwall/v1/join` and `/sync` with that limit, and to the Join button.

## Down: what a follower takes

### Trust classes

| Class | Applied | Examples |
|---|---|---|
| **Tightens** | at once | new blocks, a stricter delay or exception, `fail_open` off, `enforce_age_on_download` on, takedowns, tamper flags |
| **Loosens** | bounded: the floor, a hold-down, the late-news rule | a lower delay, a new or shorter exception, `fail_open` on, a block lifted, an earlier observation time |
| **Never** | not in the protocol | upstream URLs, mirrors, registries, tokens, caches, listeners, `public_url`, trusted proxies, client IP settings, the follower's own shield wall settings and floor, clearing a tamper flag |

The last class matters most. A leader that could change a follower's upstream could send it to a malicious mirror
whose metadata and bytes agree with each other; then every check passes.

### Policy

The leader sends a bundle (`default_delay_days`, `fail_open`, per-ecosystem `fail_open`, `enforce_age_on_download`,
`exceptions`) with a version that grows whenever its content changes. The follower ignores a bundle no newer than
the last one it took (rollback protection). A leader restored from a backup sees the higher version its followers
report and moves past it.

The follower's effective policy (`shieldwall/policy.py`):

- **Stricter wins** against the policy keys the follower sets itself, in its config file or environment. Its
  defaults don't count, so the shipped configs leave those keys commented out. Delays take the maximum; `fail_open`
  is on only if both sides allow it; the download check is on if either side wants it.
- **The floor:** no delay from the leader goes below `SLOWSHIELD_SHIELDWALL_MIN_DELAY_DAYS` (1 day), exceptions for
  single versions included. A leader that is taken over can't release a package early everywhere with one exception.
- **The follower's own exceptions keep their authority** over the leader's default delay; a stricter rule from the
  leader for the same package still applies.
- **A looser bundle waits an hour.** Until then the stricter of the old and the new applies, and the Shield wall page
  shows what is waiting. A newer bundle restarts the wait. Tightening never waits: the worker that syncs applies it
  at once, every other worker within a second.

The result replaces the config like a reload, so cached evaluations are dropped. The Shield wall page lists each
policy key three times: as this instance sets it, as the leader sets it, and what applies.

### Data

The leader logs a change (a row in `shieldwall_changes`, moved to a new sequence number on every change) whenever
something followers take changes, by database triggers that only fire on a leader. Becoming a leader logs
everything that exists. A follower asks for changes after its cursor, up to 500 at a time.

| Data | Merge on the follower | Class |
|---|---|---|
| The leader's `[[blocks]]` | added to the follower's own blocks as `source = 'leader'` rows; clients read "blocked by the administrator" | tightens |
| The leader's GitHub advisory rows | the same, but only for followers without their own GitHub token | tightens |
| A block the leader lifts or deletes | the follower lifts its copy after 24 hours, unless the leader blocks it again first | loosens |
| OSV rows | not sent: every instance reads OSV itself | |
| Takedowns (`oci_digests.gone`) | the earliest wins | tightens |
| Tamper flags (`artifacts.tampered`) | set on the follower, with a `tampered` event; never cleared by the leader | tightens |
| OCI tag history (`oci_tags`) | `first_seen` = the earlier of the follower's and the credited time | loosens |
| Maven and Cargo `first_listed` | the earlier of the follower's and the credited time | loosens |
| `oci_since` | at pairing only: the earlier of both, so a new follower skips the fail-open window the leader is past | loosens (bootstrap) |
| Registry times (PyPI, npm, Go, Maven files, OCI `registry_time`) | not sent: the follower reads them from the registry itself | |

### The late-news rule

SlowShield's own observations (when it first saw a tag point to a digest, when it first saw a Maven version listed)
can't be checked by anyone else. A leader that is taken over could claim it saw a malicious digest ten days ago, and
a follower would serve it at once; the floor doesn't help, because the delay isn't lowered, the clock is moved.

So the follower records, for every sync, its own time and the leader's change head (`shieldwall_sync_log`). An
observation that arrives at local time R with sequence number s, claiming time T, is credited with

    credited = max(T, W(s) − 10 minutes, R − 24 hours)

where W(s) is the last sync at which the leader's head was still below s: the last moment the follower *knows* the
entry didn't exist. A genuine observation, logged within seconds, keeps its time. An entry created now that claims
last week is credited about ten minutes. Entries logged during an outage are credited back to its start, and never
more than a day. Changes that existed before the follower paired are the bootstrap and are taken as they are:
pairing trusts the leader's past, and the operator confirmed that leader. The rule is modelled on Certificate
Transparency's maximum merge delay; it is this project's own construction and deserves review.

## Up: reports, exactly once

- **The outbox.** Every recorder flush (every 5 seconds) writes its batch to the local statistics and, in the same
  transaction, to `shieldwall_outbox` while the follower is paired. So does the first fingerprint of every file it
  serves.
- **Delivery.** A sync sends up to 200 entries (4 MB), oldest first. The leader applies them in order, at most once
  each, by a high-water mark per follower, and acknowledges the mark; the follower deletes what was acknowledged,
  never past the last entry that request carried.
  A retried sync can't count anything twice. A follower that can't reach its leader for days keeps queueing and
  drains the queue afterwards; entries older than 30 days are dropped.
- **History at pairing.** The follower queues its statistics tables as they are, its retained events and the
  packages it served, in the transaction that makes it active. Nothing is lost or counted twice at the seam.
- **On the leader** every statistics row and event carries the instance it came from (`instance`, empty for the
  leader's own). The overview, the security timeline and the CSV cover all instances by default, and narrow to one
  follower, a location or a label (`?in=`). The Shield wall page lists the followers with their last sync and
  queue.
- **Client IPs** go up with events, unless the follower doesn't record them (`SLOWSHIELD_RECORD_CLIENT_IP=false`).
- **Fingerprints.** The leader compares every follower's first fingerprint of a file with its own. Different bytes
  for the same file mean one of them was served something else, or that the follower is lying. The leader records a
  `tampered` event for that follower and refuses the file **on that follower only**, which no other follower hears
  of: a follower's word never refuses a file anywhere else, so a follower that is taken over can only block itself.
  Followers that disagree among themselves, on a file the leader has no fingerprint for, are recorded as an
  `integrity_mismatch` event for the operator. Fingerprints followers report are never sent down as references.

## Files through the leader

A follower that misses its cache asks the leader first (`SLOWSHIELD_SHIELDWALL_VIA_LEADER`, on by default):

- **What goes:** files with a content address (a sha256 from the index or from the follower's first download, or
  npm's sha512), fetched without credentials and without reading registry headers. Today that is PyPI, npm and Cargo
  files, and any file the follower has seen before. Metadata never goes through the leader.
- **The leader** (`GET /_shieldwall/v1/blob?sha256=…&url=…`, signed by a member) answers from its cache by content
  address, or fetches the URL, but only from its own configured upstream hosts, streams it back, and caches it if
  the bytes match the address. Its cache is keyed by content, so a follower can't put bytes under another file's
  name. npm files are found again by their sha512 (`shieldwall_blobs`).
- **The follower checks every byte** as if it came from the registry. Bytes that don't match are an integrity
  failure of the leader, not a tamper flag on the file, and the follower skips the leader for a minute.
- **When the leader can't answer** (down, slow to connect, any status but 200), the request goes to the registry
  and the leader is skipped for a minute. A transfer that breaks off midway fails that one download.
- **Statistics:** `leader_bytes` counts what came through the leader.

## When the leader is gone

Nothing on the request path waits for the leader. The follower keeps serving with its own feeds, its own cache, and
the last policy and blocks it took; its outbox grows. The sync retries with backoff from 5 seconds to 5 minutes. A
looser policy that was already waiting applies when its hour is up, and a lifted block when its day is up. When the
leader comes back, the outbox drains and changes arrive under the late-news rule.

## Configuration

| Variable | Config key | Default | Meaning |
|---|---|---|---|
| `SLOWSHIELD_SHIELDWALL_ROLE` | `shieldwall.role` | the role it had, else `standalone` | `leader` on the leader; a join string makes an instance a follower; `standalone` leaves the shield wall |
| `SLOWSHIELD_JOIN`, `SLOWSHIELD_JOIN_FILE` | `shieldwall.join` | | the join string; needed until the follower has joined |
| `SLOWSHIELD_JOIN_CONFIRM` | `shieldwall.join_confirm` | `ui` | `auto` joins without the click |
| `SLOWSHIELD_INSTANCE_NAME` | `shieldwall.name` | the host name | shown on the leader |
| `SLOWSHIELD_INSTANCE_LOCATION` | `shieldwall.location` | | the leader's views filter by it |
| `SLOWSHIELD_INSTANCE_LABELS` | `shieldwall.labels` | | `env=prod,team=ml` |
| `SLOWSHIELD_SHIELDWALL_MIN_DELAY_DAYS` | `shieldwall.min_delay_days` | `1` | the follower's floor |
| `SLOWSHIELD_SHIELDWALL_VIA_LEADER` | `shieldwall.via_leader` | `true` | package files through the leader |
| `SLOWSHIELD_LEADER_CA_FILE` | `shieldwall.leader_ca_file` | | a leader whose certificate a private CA signed |

Shield wall settings need a restart. The Helm chart has a `shieldwall` section (`role`, `joinSecret`, `name`,
`location`, `labels`, and `leaderEgress` for a leader on a private network under the network policy); Compose passes
the variables through.

## Safety

| Threat | Mitigation | What remains |
|---|---|---|
| A leader that is taken over | the floor; the hour's wait and the page that shows it; blocks are a union with the follower's own feeds; the late-news rule; evidence direct and every byte checked; the "never" class | after an hour it can lower delays to the floor; it can backdate observations by about one sync (a day after an outage); after a day it can lift GitHub-only blocks on followers without a token; it can deny service with bogus blocks or tamper flags, and stop syncing (the page shows the sync age) |
| A leader taken over before a follower pairs | none beyond the floor: pairing trusts the leader's past | planted history is accepted; said so on this page |
| A follower that is taken over | everything is attributed to it; its fingerprints are checked and compared, and refuse files on that follower only; the leader fetches only from its own upstream hosts; `wall remove` | polluted statistics until removed; it sees the policy and blocklist; it could fetch too-new files through the leader, as it could directly |
| Someone with the join string | single use, 10 minutes; bound to the follower's key; the follower checks the leader's key hash | whoever uses it first joins; the operator sees every follower on the leader |
| Someone on a follower's UI | the leader comes from the environment; Join only confirms it, from the page itself | they can click Join for the leader the operator configured |
| A network attacker | TLS (the leader's URL must be https); signatures on every message, responses bound to their requests; only a signed refusal removes a follower; acknowledgements never delete reports that weren't sent | none beyond TLS's own |
| Skewed clocks | ±5 minutes on signatures; the late-news rule runs on the follower's clock | policy depends on clocks anyway |

## Why a protocol of its own

- **Replication doesn't fit.** Litestream and LiteFS have one writer, so followers couldn't work on their own;
  rqlite and dqlite need a quorum; cr-sqlite and Corrosion merge every row from every peer with no notion of trust.
  The data is small and of a few kinds; a protocol that merges each kind under its trust class is less code.
- **Borrowed models:** k3s and kubeadm join tokens (fetch the key, check its hash), Syncthing's pinned identities,
  RFC 9421 message signatures, TUF's monotonic versions, rqlite's change-data-capture high-water mark for the outbox,
  Squid's and Nexus's parent caches with a breaker, and containerd's split between resolving (trusted, direct) and
  fetching by digest (self-checking, through the leader).
- **Tailscale is an optional hook, not a requirement.** The protocol is plain HTTPS, so it runs over a tailnet as
  is. tailcat (pre-1.0, Go only) solves reachability, which followers that dial out don't need.

## Not yet

- **Tailscale:** auto-approval through an app capability in a grant (LocalAPI WhoIs), and finding the leader.
- **Inviting and removing in the UI,** once the UI has authentication.
- **Container images through the leader:** they need registry tokens on the leader's side.
- **Compacting the change log,** and a fresh snapshot for a follower whose cursor is below it.
- **Resuming** a transfer that broke off midway (HTTP Range); collapsing concurrent misses on the leader.
- **Promoting a follower** to leader, and backing up the leader's key.
- **Metrics** per follower in OTLP (`service.instance.id`).
