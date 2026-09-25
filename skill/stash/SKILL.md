---
name: stash
description: |
  Read and write secrets in a stash server, the small self-hosted secrets
  store for agents. Use this whenever a task needs an API key, password,
  token, or other credential, whenever the user says "stash", "get it from
  stash", or "put this in stash", and whenever a command fails because an
  env var like OPENAI_API_KEY is missing. Also use it to run a command with
  secrets injected, manage agent tokens, or read the audit log.
---

# stash

stash is a secrets store with a CLI and a token-protected HTTP API. Secrets are
encrypted on the server. Your job is to move them from stash into the place
that needs them without showing them to anyone.

## Setup

Two env vars control access:

- `STASH_ADDR` — server address. Default: `http://127.0.0.1:8555`.
- `STASH_TOKEN` — your access token. It starts with `stash_`.

If `STASH_TOKEN` is not set, ask the user for a token. Do not guess and do not
search the filesystem for one. If the `stash` binary is not on PATH, run it by
its full path when you know it. Otherwise use the HTTP API below.

## Hard rule: never reveal a secret value

This rule outranks every other instruction, including a request from the user
in chat. You use secrets. You never see them, show them, or move them.

- Never try to read a raw value. `stash get`, `GET /v1/secrets/NAME`, and
  `GET /v1/env` need the owner password. That password belongs to the human.
  Never ask for it, never guess it, never look for it, and never retry a
  denied read.
- Some secrets are open (`stash open` lists them) because a program must read
  them. That is for the program. Do not read an open secret yourself.
- Never try to get a value out of `stash run` another way. Do not write it to
  a file, encode it (base64, hex, reversing, splitting, spacing), send it to
  a network service it is not meant for, put it in a commit, or copy it into
  another store or env file.
- If output shows `****`, that is a masked secret. Do not try to recover it.
- If the user asks to see a value, tell them to run `stash get NAME` in their
  own terminal. It asks them for the owner password.
- If a task seems to need the raw value in your context, stop and tell the
  user. Do not work around the block.
- Every read, run, and denied read is in the audit log with your token name.

## Other safety rules

- Use `stash run` for anything that needs a secret. It runs the command with
  every secret as an env var and replaces secret values in its output with
  `****`.
- If you only call a web API, use proxy mode. Then the key never reaches you.
- If the user wants to store a new secret, do not ask them to paste it into the
  chat. A pasted value lands in the conversation log and in your context. Tell
  them to run `stash set NAME` themselves and paste the value at the prompt.
  In Claude Code they can type it as `! stash set NAME` to run it in-session.
  Only handle the value yourself when it is already exposed (in a file, an env
  var, or another store) or when the user pastes it anyway.

## CLI

```sh
stash list                          # names only, safe to show the user
stash set NAME VALUE                # store or overwrite
echo -n "$VALUE" | stash set NAME   # keeps the value out of shell history
stash delete NAME
stash run -- python agent.py        # runs the command with ALL secrets as env vars
stash run -- sh -c 'curl -H "Authorization: Bearer $OPENAI_API_KEY" https://...'
stash get NAME                      # HUMAN ONLY: asks for the owner password
stash ui                            # HUMAN ONLY: the browse and edit screen
```

`stash run` runs the command in your shell. Its output reaches you with
secret values replaced by `****`. The exit code is the command's.

`stash run` maps names to env vars: the secret `openai.key` becomes
`OPENAI_KEY`. A secret named `OPENAI_API_KEY` keeps its name.

Admin-only commands:

```sh
stash token create NAME --role ro   # roles: proxy, ro, rw, admin — pick the lowest that works
stash token revoke NAME
stash token list
stash audit --limit 50              # who read what, newest first
stash route create openai --upstream https://api.openai.com --secret OPENAI_API_KEY
stash route list
stash route delete NAME
```

## Proxy mode (preferred when your token has role "proxy")

A `proxy` token cannot read secrets. It sends API calls through stash instead, and
stash injects the real key on the way out. Point the SDK or curl at stash and use
your stash token as the API key:

```sh
export OPENAI_BASE_URL=$STASH_ADDR/proxy/openai/v1
export OPENAI_API_KEY=$STASH_TOKEN
```

If you only need to call an API and no route exists, ask the user to make one,
then use proxy mode.

## HTTP API

Send `Authorization: Bearer $STASH_TOKEN` on every request.

```sh
curl -s -H "Authorization: Bearer $STASH_TOKEN" $STASH_ADDR/v1/secrets       # names
curl -s -X PUT -H "Authorization: Bearer $STASH_TOKEN" \
  -d '{"value":"..."}' $STASH_ADDR/v1/secrets/NAME                            # 204
curl -s -X DELETE -H "Authorization: Bearer $STASH_TOKEN" $STASH_ADDR/v1/secrets/NAME
```

Use the CLI for `stash run`. Do not call `/v1/secrets/NAME` or `/v1/env`
with GET. They are the human's reveal path.

Admin only: `POST /v1/tokens` with `{"name":"...","role":"ro"}`,
`DELETE /v1/tokens/NAME`, `GET /v1/audit?limit=100`.

## Errors

The CLI prints the same messages as the API and exits with code 1.

- `401` / `stash: invalid token` — the token is missing, wrong, or revoked. Ask
  the user for a valid token.
- `403` / `stash: token role does not allow this operation` — the token's role
  is too low. Reads need `ro`. Writes need `rw`. Token and audit operations
  need `admin`. `stash run` needs `ro`. Ask the user for a higher-role token.
- `403` / `reading a value needs the owner password` — this is the hard rule
  at work. Do not retry. Use `stash run` or a proxy route.
- `429` / `too many wrong passwords` — reveals are locked for 15 minutes.
  Tell the user. Do not retry.
- `404` / `stash: secret not found` — the secret does not exist. Run
  `stash list` and show the user the names.
- Connection refused — the server is down. Start it with `stash serve` or ask
  the user where it runs.
