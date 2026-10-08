# Secrets

`github_token.empty` is an intentionally empty placeholder so the stack starts without a token
(the GitHub Advisory feed then stays off and the UI explains how to enable it).

To enable the feed:

```sh
printf %s 'github_pat_…' > secrets/github_token   # this file is git-ignored
chmod 600 secrets/github_token
echo 'GITHUB_TOKEN_SECRET_FILE=./secrets/github_token' >> .env
docker compose up -d
```

`leader-ca.empty` is the same for a shield wall follower (docs/design/shieldwall.md). A follower must trust its
leader's certificate, and a leader running this stack with its default `SLOWSHIELD_TLS_MODE=internal` has one signed
by Caddy's own private CA, which nothing trusts. Without that CA the follower can't discover, join or sync, and its
Shield wall page says the leader's certificate isn't trusted. Give the follower that CA certificate:

```sh
# on the leader
docker compose exec caddy cat /data/caddy/pki/authorities/local/root.crt > leader-ca.crt
# on the follower
cp leader-ca.crt secrets/leader-ca.crt
echo 'LEADER_CA_SECRET_FILE=./secrets/leader-ca.crt' >> .env
docker compose up -d
```

A leader with a publicly trusted certificate (ACME) needs none of this.
