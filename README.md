# stash

A tiny secrets store for AI agents. One 7 MB binary, one encrypted file.

```sh
go install github.com/FatherMarz/stash@latest

stash serve                        # prints your admin token, once
export STASH_TOKEN=stash_...
stash password set                 # the owner password, typed at a terminal
stash set OPENAI_API_KEY sk-...    # store a secret
stash get OPENAI_API_KEY           # read it back (asks for the owner password)
stash run -- python agent.py       # run anything with all secrets as env vars
stash ui                           # browse, search, and edit on one screen
```

## Agents use secrets, they never see them

Once you run `stash password set`, a token can list names, write, run
commands, and proxy, but it cannot read a value. Reading a value needs the
owner password, typed at a terminal. Agents do not have it. Five wrong tries
lock reveals for 15 minutes. Until you set a password, stash reads as before.

`stash run` works as before, in your own shell. Secret values in its output
show as `****`. The server hands the values only to the stash program itself
on the same machine, so `curl` with a token gets nothing.

A program that must read one raw value, like a credential helper, needs that
secret open: `stash open NAME`. Any token can read an open secret. `stash open`
lists them. `stash close NAME` locks one again.

An agent that sets out on purpose to leak a key it uses (write it to a file,
encode it) can still do it. Proxy mode is the only full stop: the key never
reaches the agent's process.

## Upgrading from 0.2

Nothing locks until you set a password, so the upgrade itself breaks nothing.

1. Stop the server and replace the binary. On macOS, copy the new file next
   to the old one and `mv` it over. A plain `cp` over the old file makes
   macOS kill the program.
2. Start the server again.
3. Find every script that reads a raw value: `stash get`, or a direct call
   to `/v1/secrets/NAME` or `/v1/env`. Move each one to `stash run`. If it
   must have the raw value (a credential helper, say), run `stash open NAME`.
4. Run `stash password set` in a terminal, with an admin token. The lock is
   now on. If you lost the admin token, stop the server and run
   `stash reset-admin`.
5. Copy the new agent skill: `cp -r skill/stash ~/.claude/skills/stash`.

## Browse and edit: stash ui

`stash ui` opens one screen with every secret. `/` searches, and tab
completes. Enter shows a value and c copies it. Both ask for the owner
password once per session. e edits, n adds, r renames, d deletes. g puts a
secret in a group you name. Without one, it groups by its first word
(`VIGI_KEY` goes under VIGI). o opens or closes a secret for scripts, with an
admin token.

## Give each agent its own token

```sh
stash token create my-agent --role ro
stash token revoke my-agent
stash audit                        # who read what, when
```

Roles: `ro` reads, `rw` reads and writes, `admin` manages everything, `proxy` reads nothing — see below.

## Proxy mode: the agent never sees the key

```sh
stash route create openai --upstream https://api.openai.com --secret OPENAI_API_KEY
stash token create my-agent --role proxy
```

Point the SDK at `http://127.0.0.1:8555/proxy/openai/v1` with the proxy token as its API key.
stash puts the real key on each request on the way out. A proxy token cannot read any secret.

## Notes

- Lost the owner password? Stop the server and run `stash reset-password`.
- Secrets are AES-256-GCM encrypted in `~/.stash/stash.db`. The key is `~/.stash/stash.key`. Back up both. Keep them apart.
- stash listens on `127.0.0.1` only. If you expose it, add `--tls-cert` and `--tls-key`.
- `stash help` lists every command. Each command maps to an HTTP route under `/v1/`.
- `cp -r skill/stash ~/.claude/skills/stash` teaches Claude Code how to use it. Other agents can load the same file.
- No web UI, no rotation, no clustering. If you need those, use Infisical or OpenBao.

MIT.
