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
secret open: `stash open NAME`. Any token can read an open secret.

An agent that sets out on purpose to leak a key it uses (write it to a file,
encode it) can still do it. Proxy mode is the only full stop: the key never
reaches the agent's process.

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
- No UI, no rotation, no clustering. If you need those, use Infisical or OpenBao.

MIT.
