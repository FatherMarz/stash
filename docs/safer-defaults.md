# Upgrade to Stash 0.6

These changes require updates to existing `stash run` commands. They do not change saved secret values or tokens.
Existing 0.5 owner and agent tokens continue to work. Versions before 0.5 need the setup procedure in [the older-version guide](upgrade-0.5.md).
Back up the store, encryption key, installed binary, and service definitions before replacement.
Keep the current service running during planning. Stop it before copying the database or replacing the binary.
Restart the updated service before running new owner connection commands.
The public health response reports its version and access-policy capabilities.
Confirm that the running server and CLI both use 0.6.0 before applying a batch.
Use `stash route list --json` to export complete connection metadata without values.

## Agent work

1. Find the program's required secret names.
2. Run `stash list --json` to inspect their paths.
3. For a blocked API key, prepare an owner command with the service's real upstream and authentication header.
4. For a database password, prepare a direct connection command only if the program needs the real value.
5. Give the owner those commands to run in their own terminal.
6. Configure the client to use the provided proxy URL.
7. Add one `--secret NAME` option for each required secret.
8. Restart the program after its connections are ready.

The agent must not request owner tokens, passwords, or secret values in chat.
The agent must not change a blocked API key to direct access to make a request pass.

## Owner commands

The following examples use secret names and example endpoints. Replace them with the service's real details.
Use the owner token only in your own terminal. Do not send that token to the agent.

For an HTTP API with bearer authentication:

```sh
stash route create service --upstream https://api.example.com --secret SERVICE_API_KEY
```

For an API with a custom authentication header:

```sh
stash route create service --upstream https://api.example.com --secret SERVICE_API_KEY --header 'x-api-key: {value}'
```

For a database URL that the program must receive directly:

```sh
stash route create database --secret DATABASE_URL --direct
```

Existing AWS profiles continue to use `stash aws connect`. The raw AWS keys do not enter `stash run` children.
New connection definitions cannot share a secret with another connection.
If existing profiles reuse a key pair, consolidate their connection definitions before changing them.

## Update run commands

An unscoped command now fails:

```sh
stash run -- python agent.py
```

Name only the required secrets:

```sh
stash run --secret OPENAI_API_KEY -- python agent.py
stash run --secret OPENAI_API_KEY --secret DATABASE_URL -- python agent.py
```

The second command requires an owner-approved direct connection for `DATABASE_URL`.
If one selected name is blocked, the entire request fails before the child starts.
The server rejects missing or empty selections, including requests from older clients.

## Limits

Proxy connections keep the real credential out of the child program on supported requests.
Direct connections give the program the real value. Output masking covers matching values of at least eight bytes.
That masking does not cover shorter values, encoded output, or files.

stash does not isolate an agent that can read its storage files or control your operating-system account.
