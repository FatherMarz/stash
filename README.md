# stash

A small secrets store for agents. One Go binary, encrypted local storage, and an audit log.

stash has one token and one owner password. Agents use the token. The person types the password for owner actions.

## Setup

Use Go 1.26.11 or newer on macOS or Linux. The preferred build toolchain is Go 1.27.4.
After installation, put Go's bin directory on your PATH.

```sh
go install github.com/FatherMarz/stash@latest
```

Run setup in your own terminal, with the server stopped:

```sh
stash setup
```

Setup does these things:

1. It makes the stash token and puts it in `~/.stash/token`.
2. It adds one line to `~/.zshrc` (or `~/.bashrc`) that loads the token into `STASH_TOKEN`.
3. It asks you to choose the owner password.
4. It reports the proxy, direct, and blocked secrets.
5. It moves every AWS profile that read its keys with `stash get` to stash signing.

Then start the server and leave it running:

```sh
stash serve
```

Background jobs do not load `~/.zshrc`. The CLI reads `~/.stash/token` by itself when `STASH_TOKEN` is empty.
You can run setup again at any time. It keeps the token and the password.

## The token and the password

- **Token:** lists names and paths, adds new secrets, and starts `stash run`. It works only through the stash program, so `curl` with it fails.
- **Owner password:** every owner action asks for it. Owner actions read a value, change or delete a secret, add or change a path, and manage tokens and the audit log.

Agents can read the token. The token alone cannot read a value or change a path.
After five wrong passwords, owner actions lock for 15 minutes. Runs keep working.

## Secret access

`stash list --paths` shows how a program can use each secret. No run receives secrets until it names them.

| Path | Secrets | What the program gets |
| --- | --- | --- |
| proxy | API keys with a known site, and AWS key pairs | Never the key. For an API key: a stand-in and a `NAME_BASE_URL`. stash adds the real key on the way out, only to that site. For AWS: the profile sends each call through stash, and stash signs it. |
| direct | Secrets that the owner approved for direct use | The real value. Captured output masks matching values of at least eight bytes. |
| blocked | Secrets with no path | Nothing. The run fails before it starts the program. |

A proxy works only for calls to a website or AWS. A program that logs in to a database or signs data itself must hold the real value.
The direct path does not stop deliberate disclosure. Programs can write values to files or encode them before output.
stash does not isolate an agent with access to your storage files or operating-system account.

## Paths in stash ui

```sh
stash ui
```

The screen asks for the owner password once, when it opens.
Blocked secrets show at the top. Each secret shows its path: the site, direct, or its AWS profile.

Select a secret and press `p`:

- `s` site: type the API's site address and its key header. The default header is `Authorization: Bearer {value}`.
- `d` direct: the program gets the real value. Use this only for a database password or a signing secret.
- `a` AWS: type the profile name and the secret that holds the access key ID. The selected secret is the secret access key.
- `x` remove: the secret becomes blocked.

Before it saves a site, the screen shows the site that the key will go to. Read it before you press `y`.

### Built-in sites

| Secret name | Fixed site |
| --- | --- |
| `OPENAI_API_KEY` | `https://api.openai.com/v1` |
| `ANTHROPIC_API_KEY` | `https://api.anthropic.com` |
| Names with `OPENROUTER` that end in `API_KEY` | `https://openrouter.ai/api/v1` |

### When an agent finds a blocked secret

A run that names a blocked secret stops and tells the agent what to do.
The agent finds the API's site address and key header in the API's documentation.
It gives you three lines: the secret, the site, and the header. You type them in `stash ui`.
The agent never needs the password or a value.

### Paths from the command line

The same changes work as commands. Each one asks for the owner password.

```sh
stash route create service --upstream https://api.example.com --secret SERVICE_KEY
stash route create virustotal --upstream https://www.virustotal.com --secret VIRUSTOTAL_API_KEY --header "x-apikey: {value}"
stash route create database --secret DATABASE_URL --direct
stash aws connect my-profile --key-id MY_KEY_ID --secret-key MY_SECRET_KEY
```

## AWS

An AWS path writes the profile in `~/.aws/config`. The profile gets a one-hour run token from stash and
sends its calls to `http://127.0.0.1:8555/aws/my-profile`. stash signs each call with the real key pair
and sends it to the AWS host for that service and region. The key pair never leaves stash.
Presigned URLs and signed-chunk uploads cannot go through stash.

API Gateway is blocked by default. An owner can approve one exact hostname and
specific GET paths with `--read-api-host` and repeated `--read-api-path` options.
See [API Gateway connection setup](docs/aws-read-api.md).

On macOS, the local CLI uses a private socket when available. See [local control](docs/local-control.md).

## Run a program

```sh
stash run --secret OPENAI_API_KEY -- python agent.py
stash run --secret OPENAI_API_KEY --secret DATABASE_URL -- python agent.py
```

Repeat `--secret` for each required secret. An omitted or empty selection fails.
Each `stash run` gets its own run token. The run token works only for that program's proxy paths.
It ends when the program exits. A server restart ends every run token. Restart long-running programs after a server restart.

## Agent-led setup

1. Inspect the application to find its secret names and API sites.
2. Install stash with the Go command above.
3. Ask the person to run `stash setup` in their terminal with the server stopped.
4. Start `stash serve` through the existing service or terminal.
5. Ask the person to store new values with `stash set NAME` in their terminal.
6. Run `stash list --json` to inspect names and paths without reading values.
7. For each blocked secret, give the person the secret, site and header to type in `stash ui`.
8. Configure the application to use its `NAME_BASE_URL`.
9. Start it with the smallest `--secret` selection.

Do not ask for secrets or the owner password in chat.

## Owner commands

Each command asks for the owner password at a hidden prompt.

```sh
stash ui
stash get NAME
stash set NAME                     # a new name needs no password
stash rename OLD NEW
stash delete NAME
stash password set
stash token list
stash audit --limit 50
```

If you lose the password, stop the server, run `stash reset-password` in your terminal, then run `stash setup`.

## Upgrade to 0.7

0.7 has no owner token. Secrets, paths, and the password stay.

1. Stop the server.
2. Replace the binary. On macOS, copy the new binary beside the old one, then rename it over the old one.
3. Run `stash setup` in your own terminal. It keeps the agent token as the one token and ends the owner token.
   It comments out old `export STASH_TOKEN=` lines in your shell files.
   If no password is set, it asks you to choose one.
4. Start the server, then restart programs that use `stash run`.

Versions before 0.5 need [the older-version guide](docs/upgrade-0.5.md) first.

Secrets use AES-256-GCM encryption in `~/.stash/stash.db`. Back up the database and `~/.stash/stash.key` together.
Stash listens on loopback by default. For remote access, configure TLS.

MIT. Built by Marcello Delcaro, AI-assisted.
