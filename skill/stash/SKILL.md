---
name: stash
description: Use stash when a task needs an API key, AWS access, a database URL, or another credential. Agents use secrets through stash run and never read values.
---

# stash

Use the `stash` CLI. It finds its own agent token. Do not read `~/.stash/agent.token`, and never ask for the owner token or password.
`STASH_ADDR` changes the server address from `http://127.0.0.1:8555`.

## Inspect access

`stash list` shows each secret and its path.

- **proxy**: the program never holds the key.
  - API keys with a known site: the program gets a run token in `NAME` and the proxy URL in `NAME_BASE_URL`.
    Point the SDK or HTTP client at `NAME_BASE_URL`. stash adds the real key, only for that site.
  - AWS key pairs: use the AWS profile, for example `aws --profile my-profile ...`. stash signs each call.
    Do not ask for AWS keys.
- **direct**: the owner approved a direct connection. The program gets the real value in `NAME`.
  Captured output masks matching values of at least eight bytes. This does not prevent deliberate disclosure.
- **blocked**: no connection exists. Do not start the program or request the raw value.
  Prepare the exact connection command for the owner to run.

## Run a program

```sh
stash run --secret OPENAI_API_KEY -- python agent.py
stash run --secret OPENAI_API_KEY --secret DATABASE_URL -- python agent.py
```

Select only the secrets that the program needs. Repeat `--secret` for each one.
Missing or empty selections fail. There is no implicit access to the full store.
The database example requires an owner-approved direct connection.

A program that hard-codes an API address bypasses the proxy and fails with a run token.
Change it to read `NAME_BASE_URL`.

## Store a secret

`stash set NAME` adds a new secret (value from stdin). Changing an existing secret needs the owner.
Never ask the user to paste a value into chat. Tell them to run `stash set NAME` in their own terminal.

## Lead setup for the user

1. Read the application's integration code to find required secret names and endpoints.
2. Install stash with `go install github.com/FatherMarz/stash@latest` if it is absent.
3. If setup is incomplete, tell the user to stop the server and run `stash setup` in their own terminal.
4. Tell the user to save the owner token in their password manager.
5. Start the server through its existing service or terminal workflow.
6. Give the user `stash set NAME` commands for missing values.
7. Run `stash list --json` to inspect names and paths.
8. Prepare owner connection commands for the blocked names that this application needs.
9. Configure the application to use its provided proxy URLs.
10. Start it with the smallest explicit secret selection.
11. Check a harmless service request without printing credentials.

Do not repeat setup or reset owner access if the existing agent connection works.

For a blocked API key, identify the real service URL and its authentication header.
Give the owner a command such as:

```sh
stash route create service --upstream https://api.example.com --secret SERVICE_API_KEY
stash route create service --upstream https://api.example.com --secret SERVICE_API_KEY --header 'x-api-key: {value}'
```

These are alternative authentication examples. Choose the command that matches the service.
Do not run owner commands with agent credentials or ask for the owner token.

For a database URL or signing secret that the program must hold, explain the direct-access consequence.
Then give the owner a command such as:

```sh
stash route create database --secret DATABASE_URL --direct
```

Do not approve direct access for an API key to bypass a missing proxy connection.
stash does not isolate an agent with access to its storage files or operating-system account.

## Rules

- Never use `stash get`, `/v1/secrets/NAME`, or `/v1/env`. They are owner operations.
- Never print, encode, copy, or write a direct value to get around the masking.
- If an API needs a connection that does not exist, prepare the complete proxy command for the owner.
- Do not inspect the store files or encryption key to bypass access rules.

## Errors

- `401`: inspect the server address and client version. If the token is revoked, the owner must restore agent access.
- `403`: the action needs the owner, or the token was used outside the stash program.
- Missing selection: add explicit `--secret NAME` options for the required secrets.
- Blocked secret: prepare a proxy or justified direct connection command for the owner.
- Connection refused: the server does not run at `STASH_ADDR`.
