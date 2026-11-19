---
name: stash
description: Use stash whenever a task needs an API key, AWS access, a database URL, or another credential, whenever the user says "stash", and whenever a command fails because an env var like OPENAI_API_KEY is missing. Agents use secrets through stash run and never read values.
---

# stash

stash has one token. Setup puts it in `~/.stash/token` and loads it into `STASH_TOKEN` from the shell start file.
The `stash` CLI finds the token by itself. You need nothing else.
Owner actions also need the owner password. Only the person types it. Never ask for it.
`STASH_ADDR` changes the server address from `http://127.0.0.1:8555`.

## Inspect access

`stash list --paths` shows each secret and its path.

- **proxy**: the program never holds the key.
  - API keys: the program gets a stand-in in `NAME` and the proxy address in `NAME_BASE_URL`.
    Point the SDK or HTTP client at `NAME_BASE_URL`. stash adds the real key, only for that site.
  - AWS key pairs: use the AWS profile, for example `aws --profile my-profile ...`. stash signs each call.
- **direct**: the owner approved it. The program gets the real value in `NAME`.
  Captured output masks matching values of at least eight bytes. This does not stop deliberate disclosure.
- **blocked**: the secret has no path. Nothing can use it.

## Run a program

```sh
stash run --secret OPENAI_API_KEY -- python agent.py
stash run --secret OPENAI_API_KEY --secret DATABASE_URL -- python agent.py
```

Name only the secrets that the program needs. Repeat `--secret` for each one.
A program that hard-codes an API address bypasses the proxy and fails. Change it to read `NAME_BASE_URL`.

## A blocked secret

If a secret is blocked, do not start the program. Do these steps:

1. Find the API's site address and key header in the API's own documentation.
2. Give the person exactly three lines:

   ```
   Secret: SERVICE_API_KEY
   Site:   https://api.example.com
   Header: Authorization: Bearer {value}
   ```

   If the API takes the key in its own header, give that header, for example `x-api-key: {value}`.
3. Tell the person: open `stash ui` in your own terminal, select the secret, press `p`, then `s`, and type the site and header.

For a database URL or a signing secret that the program must hold, tell the person to press `p`, then `d` (direct).
Say that the program then holds the real value.
Never suggest direct for an API key.

## Store a secret

You can add a new secret with `stash set NAME` (value from stdin).
Changing an existing secret needs the owner password.
Never ask the person to paste a value into chat. Tell them to run `stash set NAME` in their own terminal, or use `stash ui`.

## Lead setup for the person

1. Read the application's code to find the secret names and API sites it needs.
2. If stash is absent, install it: `go install github.com/FatherMarz/stash@latest`.
3. If `stash list` fails with "no stash token", tell the person to stop the server and run `stash setup` in their own terminal.
4. Start the server through its existing service.
5. Give the person `stash set NAME` commands for missing values.
6. For each blocked secret the application needs, give the three lines above.
7. Configure the application to use `NAME_BASE_URL`.
8. Start it with the smallest `--secret` selection.
9. Check one harmless API request without printing credentials.

## Rules

- Never ask for, guess, or type the owner password.
- Never use `stash get`, `stash ui`, `/v1/secrets/NAME` or `/v1/env`. They are owner actions.
- Never print, encode, copy, or write a direct value to get around the masking.
- Never fake a terminal to reach a password prompt.
- Do not read the store files or the encryption key.

## Errors

- "this needs the owner password": the action is the person's. Give them the command or the `stash ui` steps.
- "is blocked": follow "A blocked secret" above.
- "no stash token" or "invalid or old token": the person runs `stash setup` in their own terminal, with the server stopped.
- "works only through the stash command": use the `stash` CLI, not curl.
- Missing selection: add `--secret NAME` for each secret the program needs.
- Connection refused: the server does not run at `STASH_ADDR`.
