---
name: stash
description: Use stash when a task needs an API key, AWS access, a database URL, or another credential. Agents use secrets through stash run and never read values.
---

# stash

Use the `stash` CLI. It finds its own agent token. Do not read `~/.stash/agent.token`, and never ask for the owner token or password.
`STASH_ADDR` changes the server address from `http://127.0.0.1:8555`.

## Two paths

`stash list` shows each secret and its path.

- **proxy**: the program never holds the key.
  - API keys with a known site: the program gets a run token in `NAME` and the proxy URL in `NAME_BASE_URL`.
    Point the SDK or HTTP client at `NAME_BASE_URL`. stash adds the real key, only for that site.
  - AWS key pairs: use the AWS profile, for example `aws --profile my-profile ...`. stash signs each call.
    Do not ask for AWS keys.
- **direct** (everything else): the program gets the real value in `NAME`. stash prints it as `****` in output.

## Run a program

```sh
stash run -- python agent.py                          # every secret on its path
stash run --secret OPENAI_API_KEY -- python agent.py  # only the named secrets
```

A program that hard-codes an API address bypasses the proxy and fails with a run token.
Change it to read `NAME_BASE_URL`.

## Store a secret

`stash set NAME` adds a new secret (value from stdin). Changing an existing secret needs the owner.
Never ask the user to paste a value into chat. Tell them to run `stash set NAME` in their own terminal.

## Rules

- Never use `stash get`, `/v1/secrets/NAME`, or `/v1/env`. They are owner operations.
- Never print, encode, copy, or write a direct value to get around the masking.
- If an API needs a connection that does not exist, ask the owner to run `stash route create`.

## Errors

- `401`: old or revoked token. The user must run `stash setup` in their terminal, with the server stopped.
- `403`: the action needs the owner, or the token was used outside the stash program.
- Connection refused: the server does not run at `STASH_ADDR`.
