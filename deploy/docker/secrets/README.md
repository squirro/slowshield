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
