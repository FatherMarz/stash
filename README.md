# stash

A small secrets store for agents. One Go binary, encrypted local storage, and an audit log.

## Setup

```sh
go install github.com/FatherMarz/stash@latest
stash setup
stash serve
```

Run setup once, in your own terminal, while the server is stopped. Setup does four things:

1. It shows the owner token once. Save it in your password manager. Never put it in a shell file.
2. It stores an agent token in `~/.stash/agent.token`. The CLI uses it by itself. Agents need nothing.
3. It sorts every secret into one of three paths (see below) and prints the count for each.
4. It moves every AWS profile that read its keys with `stash get` to stash signing.

There is nothing else to choose.

## Three paths

Each secret reaches a program in one way. stash picks the path from the secret. `stash list` shows it.

| Path | Secrets | What the program gets |
| --- | --- | --- |
| proxy | API keys with a known site | A run token and a `NAME_BASE_URL`. stash adds the real key on the way out, only to that site. |
| aws | AWS key pairs | Nothing. The AWS profile sends each call through stash, and stash signs it. |
| hand-over | Everything else: database URLs, signing secrets, `.env` files, publish tokens | The real value. stash prints it as `****` in the program's output. |

The hand-over path does not stop a program that wants to leak a value. The program holds the value,
so it can write it to a file or encode it before it prints it. Use the proxy path for every API key you can.

### Proxy

Built-in connections:

| Secret name | Fixed site |
| --- | --- |
| `OPENAI_API_KEY` | `https://api.openai.com/v1` |
| `ANTHROPIC_API_KEY` | `https://api.anthropic.com` |
| Names with `OPENROUTER` that end in `API_KEY` | `https://openrouter.ai/api/v1` |

For another API, the owner adds a connection once:

```sh
stash route create service --upstream https://api.example.com --secret SERVICE_KEY
```

Point the SDK at `SERVICE_KEY_BASE_URL`. Agents cannot add or change a connection.

### AWS

```sh
stash aws connect my-profile --key-id MY_KEY_ID --secret-key MY_SECRET_KEY
aws --profile my-profile sts get-caller-identity
```

`connect` writes the profile in `~/.aws/config`. The profile gets a one-hour run token from stash and
sends its calls to `http://127.0.0.1:8555/aws/my-profile`. stash signs each call with the real key pair
and sends it to the AWS host for that service and region. The key pair never leaves stash.
Presigned URLs and signed-chunk uploads cannot go through stash.

## Run a program

```sh
stash run -- python agent.py
stash run --secret OPENAI_API_KEY -- python agent.py
```

Without `--secret`, the program gets every secret on its path. `--secret` limits the list.

Each `stash run` gets its own run token. The token works only for that program's proxy connections.
It ends when the program exits. If `stash run` dies, the token stops working within one hour.
A server restart ends every run token. Restart long-running programs after a server restart.

## Two tokens

- **Owner:** manages secrets, connections, and tokens. Reads values with the owner password.
- **Agent:** works only through the stash program. It can list names, add new secrets, and start `stash run`.
  It cannot read a value, change an existing secret, or call the proxy with `curl`.

## Owner commands

Set `STASH_TOKEN` to the owner token in that one terminal only.

```sh
stash ui
stash get NAME                     # asks for the owner password if set
stash set NAME
stash rename OLD NEW
stash delete NAME
stash password set
stash token list
stash audit --limit 50
```

If you lose your owner token, stop the server and run `stash reset-owner` in your terminal.
If you lose your password, stop the server and run `stash reset-password`.

## Upgrade to 0.5

0.5 needs fresh tokens. Older tokens stop working. Secrets, the password, and connections stay.
0.5 has no open secrets. AWS profiles that read keys with `stash get` move to stash signing.

1. Stop the server.
2. Replace the binary. On macOS, copy the new binary beside the old one, then rename it over the old one.
3. Run `stash setup` in your own terminal. Save the new owner token.
4. Start the server, then restart programs that use `stash run`.

Secrets use AES-256-GCM encryption in `~/.stash/stash.db`. Back up the database and `~/.stash/stash.key` together.
Stash listens on loopback by default. For remote access, configure TLS.

MIT. Built by Marcello Delcaro, AI-assisted.
