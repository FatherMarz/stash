# Upgrade Stash Versions Before 0.5

Use this guide for an installation older than 0.5. For 0.5 or 0.6, use the [current migration guide](safer-defaults.md).

Saved secrets stay. Legacy tokens require fresh setup. Version 0.6.1 requires explicit run selections and owner-approved connections.

## Plan before stopping anything

Find the binary and current version:

```sh
command -v stash
stash version
```

Identify the exact service or process that runs this installation.
Record its data directory, address, binary path, and service definition.
Do not assume the default data directory for a custom installation.
Do not print environment values or token files into chat.

List the active integrations and their required secret names.
Prepare proxy connections and explicit run selections before restarting those integrations.
Do not migrate by reading or re-entering secret values.

## Stage the replacement

Use Go 1.25 or newer on macOS or Linux.
Use a private staging directory before stopping the current service:

```sh
STASH_UPGRADE_STAGE="$(mktemp -d)"
GOBIN="$STASH_UPGRADE_STAGE" go install github.com/FatherMarz/stash@latest
"$STASH_UPGRADE_STAGE/stash" version
```

The staged binary must report 0.6.1. Keep its path for the replacement step.
If installation fails, leave the existing service running.

## Stop the exact service and back up

Stop only the service or process identified during planning.
Use its existing service manager or recorded process ID.
Do not use a broad command that stops unrelated Stash instances.

After the service stops, create a private backup directory.
Copy the database and encryption key together from the actual data directory.
Also preserve token files, the previous binary, AWS configuration, and service definitions.

For the default data directory, an owner can use:

```sh
umask 077
STASH_UPGRADE_BACKUP="$HOME/stash-backup-$(date +%Y%m%d-%H%M%S)"
mkdir "$STASH_UPGRADE_BACKUP"
cp -Rp "$HOME/.stash" "$STASH_UPGRADE_BACKUP/store"
cp -p "$(command -v stash)" "$STASH_UPGRADE_BACKUP/stash"
```

For a custom data directory, substitute the recorded directory before running the copy.
Do not copy a database while its service writes to it.
Keep the backup private and out of repositories.

## Replace the binary and run legacy setup

Place the new binary beside the old binary, then rename it into position.
Do not overwrite a running executable.
Use the recorded binary path rather than assuming a system directory.
A system-owned installation can require the owner's normal administrator permissions.

With the server stopped, run setup in the owner's own terminal:

```sh
stash setup
```

For a custom store, preserve its existing credential configuration and use the matching setup data directory.
Save the new owner token in a password manager.
Do not record setup's token output in chat or a log.
Setup keeps secret values and connections. It replaces legacy token roles and moves supported AWS profiles to signing.

## Restart and apply the reviewed connections

Restart the same service with its preserved configuration.
Check the public health response at the configured address.
For the default address:

```sh
curl -fsS http://127.0.0.1:8555/v1/health
```

The response must include `"ok":true`, version 0.6.1, and the safer-defaults capabilities.

For owner commands, run this in the owner's Bash or Zsh terminal.
Paste the owner token at the hidden input and press Enter:

```sh
read -r -s STASH_TOKEN
```

Then activate it for that terminal:

```sh
export STASH_TOKEN
```

Apply the reviewed proxy, direct, and AWS connection commands.
After the owner commands, run:

```sh
unset STASH_TOKEN
```

Inspect names and paths with `stash list --json`.
Unconfigured names stay blocked. Do not give unknown API keys direct access to make a request succeed.
Use the [current migration guide](safer-defaults.md) for explicit selections and client base URLs.

## Check integrations and restart dependants

Check one harmless request per active integration without printing credentials.
Start each dependent program only after its required connections work.
Use the smallest explicit `--secret NAME` selection for each program.
A Stash server restart ends old run tokens. Restart the dependent programs with their updated commands.

Remove obsolete token exports from shell configuration locally.
Do not print their matching lines into chat.
Keep the new owner token out of shell configuration files.

## Roll back if needed

Stop the exact updated service before restoration.
Preserve the failed upgrade state in another private directory.
Restore the previous binary, store, encryption key, AWS configuration, and service definitions from the backup.
Start the previous service and check its original integrations.

Do not delete the failed upgrade state. It can contain secrets added after the backup.
