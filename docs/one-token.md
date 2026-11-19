# Stash: one token and an owner password

Status: built in 0.7.0, 2026-11-19.

## What the person sees

1. Setup makes one token. It adds a line to `~/.zshrc` that loads the token into `STASH_TOKEN`. Nobody pastes a token again.
2. Setup asks for an owner password. The password is required.
3. Every owner action asks for the password at a hidden prompt.
4. `stash ui` asks for the password once, when it opens.

## What the token can do alone

- List secret names and their paths.
- Add a new secret.
- Start `stash run --secret NAME`.
- Use the proxy and AWS paths that the owner set up.

## What needs the password

- Read a value.
- Change, rename or delete an existing secret.
- Add, change or delete a path.
- Token list, audit and export.

## Paths in the UI

`stash ui` shows the path of each secret: proxy, direct, AWS or blocked.

- Add a path to a blocked secret.
- Change a path.
- Delete a path.

Proxy asks for the site address and the key header. The header default is `Authorization: Bearer {value}`.
Direct is one choice with no other fields.
AWS asks for the profile name and the key ID secret. It writes the profile in `~/.aws/config`, the same as `stash aws connect`.
The UI saves a path only after the password check.

## Agent hand-off for a blocked secret

1. A run that names a blocked secret stops with a plain message: `SERVICE_KEY is blocked. Its site is not set. Ask the owner to add a path in stash ui.`
2. The agent finds the API's site address and key header in the API's own docs.
3. The agent gives the person three values: the secret name, the site address and the header.
4. The person opens `stash ui`, picks the secret, and types the values.
5. The agent never asks for the password or a value.

The stash skill and the README tell the agent to do steps 2 and 3.

## Background jobs

launchd jobs do not load `~/.zshrc`. Stash also keeps the same token in `~/.stash/token`. The CLI reads that file when `STASH_TOKEN` is not set.

## Security facts

- Any agent can read the token. The token alone cannot read a value or change a path.
- The password is the only owner gate. `stash reset-password` must run in the person's own terminal, the same as `stash reset-owner` today.
- The server lockout after wrong passwords stays.

## Upgrade

1. Stop the server.
2. Replace the binary.
3. Run `stash setup`. It keeps the agent token as the one token, ends the owner token, comments out old `export STASH_TOKEN=` lines, and writes the zshrc line and the token file.
4. If no password is set, setup asks for one.
5. Scripts that still export a token from before 0.5 keep working. The CLI skips that old token and reads the token file.
6. Start the server, then restart programs that use `stash run`.

## Tickets

1. Setup: one token, zshrc line, token file, required password.
2. Server: owner actions check the password instead of the owner token.
3. CLI: owner commands ask for the password.
4. `stash reset-password`: own-terminal check.
5. UI: path column, add, change and delete a path.
6. Plain message for a blocked secret.
7. Skill, README, site and upgrade guide.
8. Old tokens: the CLI skips tokens from before 0.5 (MOD-127).

## Pressure test

Chorus and buyer panel on 2026-11-19. Result: launches/06-stash/chorus-one-token-2026-11-19.md (private).
