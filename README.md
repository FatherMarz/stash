# stash

A tiny secrets store for AI agents. One 7 MB binary, one encrypted file.

```sh
go install github.com/FatherMarz/stash@latest

stash serve                        # prints your admin token, once
export STASH_TOKEN=stash_...
stash set OPENAI_API_KEY sk-...    # store a secret
stash get OPENAI_API_KEY           # read it back
stash run -- python agent.py       # run anything with all secrets as env vars
```

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

- Secrets are AES-256-GCM encrypted in `~/.stash/stash.db`. The key is `~/.stash/stash.key`. Back up both. Keep them apart.
- stash listens on `127.0.0.1` only. If you expose it, add `--tls-cert` and `--tls-key`.
- `stash help` lists every command. Each command maps to an HTTP route under `/v1/`.
- `cp -r skill/stash ~/.claude/skills/stash` teaches Claude Code how to use it. Other agents can load the same file.
- No UI, no rotation, no clustering. If you need those, use Infisical or OpenBao.

MIT.
