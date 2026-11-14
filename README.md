# stash

A small secrets store for agents. One Go binary, encrypted local storage, and an audit log.

The agent prepares setup and connection commands. The owner runs commands that handle secrets or authorize connections in their own terminal.

## Setup

Use Go 1.25 or newer on macOS or Linux. After installation, put Go's bin directory on your PATH.

```sh
go install github.com/FatherMarz/stash@latest
```

For a new store, run setup in your own terminal:

```sh
stash setup
```

Save the owner token in your password manager. In a second terminal, start the server and leave it running:

```sh
stash serve
```

Return to the first terminal to add secrets and run programs. Existing stores use the migration guide instead of repeating setup.

Run setup once, in your own terminal, while the server is stopped. Setup does four things:

1. It shows the owner token once. Save it in your password manager. Never put it in a shell file.
2. It stores an agent token in `~/.stash/agent.token`. The CLI uses it by itself. Agents need nothing.
3. It reports the proxy, direct, and blocked secrets.
4. It moves every AWS profile that read its keys with `stash get` to stash signing.

The agent lists secret names and prepares the required connections. Unconfigured secrets stay blocked.

## Secret access

`stash list` shows how a program can use each secret. No run receives secrets until it names them explicitly.

| Path | Secrets | What the program gets |
| --- | --- | --- |
| proxy | API keys with a known site, and AWS key pairs | Never the key. For an API key: a run token and a `NAME_BASE_URL`, and stash adds the real key on the way out, only to that site. For AWS: the profile sends each call through stash, and stash signs it. |
| direct | Secrets with an explicit owner-approved direct connection | The real value. Captured output masks matching values of at least eight bytes. |
| blocked | Secrets without a built-in proxy or owner-approved connection | Nothing. The run fails before it starts the program or creates a run token. |

A proxy works only for calls to a website or AWS. A program that logs in to a database or signs data itself must hold the real value.

API keys need proxy connections. An unknown API key does not fall back to a direct value.
Database passwords and signing secrets can need direct access. The owner must approve that access explicitly.

The direct path does not stop deliberate disclosure. Programs can write values to files or encode them before output.
stash does not isolate an agent with access to your storage files or operating-system account.

### Proxy

Built-in connections:

| Secret name | Fixed site |
| --- | --- |
| `OPENAI_API_KEY` | `https://api.openai.com/v1` |
| `ANTHROPIC_API_KEY` | `https://api.anthropic.com` |
| Names with `OPENROUTER` that end in `API_KEY` | `https://openrouter.ai/api/v1` |

For another API, the owner adds a connection once:

First activate the owner token in your own Bash or Zsh terminal. Run this command, paste the token, then press Enter:

```sh
read -r -s STASH_TOKEN
```

The input stays hidden. Then run:

```sh
export STASH_TOKEN
```

Do not send that token to the agent. After the owner commands, run `unset STASH_TOKEN` to return to agent access.

```sh
stash route create service --upstream https://api.example.com --secret SERVICE_KEY
```

Point the SDK at `SERVICE_KEY_BASE_URL`. Agents cannot add or change a connection.

stash sends the key as `Authorization: Bearer KEY` by default. If the API uses its own header, name it:

```sh
stash route create virustotal --upstream https://www.virustotal.com --secret VIRUSTOTAL_API_KEY --header "x-apikey: {value}"
```

The program sends its stand-in key in the same header. stash swaps it for the real key.

### Owner-approved direct access

For a database password or another value that a program must hold, the owner creates a direct connection:

```sh
stash route create database --secret DATABASE_URL --direct
```

The agent can prepare this command. Only the owner can authorize the connection.
Do not use a direct connection for an API key. Configure the API's upstream and authentication header instead.
Direct connections cannot include an upstream, header, or AWS key pair.

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
stash run --secret OPENAI_API_KEY -- python agent.py
stash run --secret OPENAI_API_KEY --secret DATABASE_URL -- python agent.py
```

Repeat `--secret` for each required secret. An omitted or empty selection fails.
The CLI and server enforce this rule. There is no implicit access to the full store.
The database example requires the owner-approved direct connection shown above.

Each `stash run` gets its own run token. The token works only for that program's proxy connections.
It ends when the program exits. If `stash run` dies, the token stops working within one hour.
A server restart ends every run token. Restart long-running programs after a server restart.

## Two tokens

- **Owner:** manages secrets, connections, and tokens. Reads values with the owner password.
- **Agent:** works only through the stash program. It can list names, add new secrets, and start `stash run`.
  It cannot read a value, change an existing secret, authorize connections, or call the proxy with `curl`.

The agent-token workflow uses local process checks on macOS and Linux. It does not support remote agent-token clients.

## Agent-led setup

1. Inspect the application to identify its required secret names and API endpoints.
2. Install stash with the documented Go command.
3. Ask the owner to run `stash setup` in their terminal with the server stopped.
4. Ask the owner to save the owner token in their password manager.
5. Start `stash serve` through the existing service or terminal workflow.
6. Ask the owner to store new values with `stash set NAME` in their terminal.
7. Run `stash list --json` to inspect names and paths without reading values.
8. Prepare exact owner commands for missing proxy or direct connections.
9. Configure the application to use its provided `NAME_BASE_URL`.
10. Start it with the smallest explicit `--secret` selection.
11. Use a harmless API request to check the connection without printing credentials.

Do not ask for secrets, owner tokens, or owner passwords in chat.
If setup is already complete, use the existing agent token. Do not reset owner access to repeat setup.

## Existing scripts

Version 0.6 requires changes to scripts that used an unscoped `stash run`.
List only the secrets each script needs. Configure connections for blocked names before restarting those scripts.
See [the migration guide](docs/safer-defaults.md).

## Owner commands

Use the hidden owner-token entry above in that one terminal only.
With `stash set NAME`, enter the secret at the hidden prompt and press Enter.
For multiline data, pipe a file to the command. Inline values still work but can enter shell history.

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

## Upgrade from versions before 0.5

0.5 needs fresh tokens. Older tokens stop working. Secrets, the password, and connections stay.
0.5 has no open secrets. AWS profiles that read keys with `stash get` move to stash signing.

1. Stop the server.
2. Replace the binary. On macOS, copy the new binary beside the old one, then rename it over the old one.
3. Run `stash setup` in your own terminal. Save the new owner token.
4. Start the server, then restart programs that use `stash run`.

Secrets use AES-256-GCM encryption in `~/.stash/stash.db`. Back up the database and `~/.stash/stash.key` together.
Stash listens on loopback by default. For remote access, configure TLS.

MIT. Built by Marcello Delcaro, AI-assisted.
