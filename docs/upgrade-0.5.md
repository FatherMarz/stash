# Upgrade stash to 0.5, step by step

Time: about 10 minutes. Do every step in your own Terminal app, on the Mac that runs stash.
Never paste the owner token into an AI chat. If it ends up in one, see "Lost or leaked owner token" at the end.

What changes:

- Old tokens stop working. Your saved secrets stay.
- API keys for OpenAI, Anthropic and OpenRouter stay in stash. A program gets a stand-in key and a `NAME_BASE_URL`.
- AWS profiles that read keys with `stash get` move over by themselves. stash signs those AWS calls.
- All other secrets reach a program the same way as before, printed as `****` in its output.

## 1. See what you have now

```sh
which stash
stash version
launchctl list | grep -i stash
```

Write down two things:

- The path from `which stash`, for example `/opt/homebrew/bin/stash`.
- The name in the last column of the `launchctl` line, for example `com.jon.stash`. If there is no line, stash does not start by itself.

## 2. Back up

```sh
cp -R ~/.stash ~/.stash-backup-0.4
cp "$(which stash)" ~/stash-0.4-binary
[ -f ~/.aws/config ] && cp ~/.aws/config ~/.aws/config.pre-stash-0.5
```

## 3. Get the new version

If `go version` says "command not found", run `brew install go` first.

```sh
mkdir -p /tmp/stash-new
GOBIN=/tmp/stash-new go install github.com/FatherMarz/stash@latest
/tmp/stash-new/stash version
```

The last line must say `0.5.0`.

## 4. Stop the stash server

If step 1 showed a `launchctl` name, use it in place of `LABEL`:

```sh
launchctl bootout gui/$(id -u)/LABEL
```

If step 1 showed no name:

```sh
pkill -f "stash serve"
```

Check that it stopped. This line must print nothing:

```sh
pgrep -fl "stash serve"
```

## 5. Put the new version in place

On a Mac, copy the new file next to the old one, then rename it over the old one. A plain copy over the old file makes macOS kill it.

```sh
OLD="$(which stash)"
cp /tmp/stash-new/stash "$OLD.new"
mv "$OLD.new" "$OLD"
stash version
```

The last line must say `0.5.0`.

## 6. Run setup

```sh
stash setup
```

Setup prints how many secrets went to each path. It lists each AWS profile that it moved. Then it shows the owner token once.

Copy the owner token into your password manager now. Do not put it in `~/.zshrc`, `~/.zshenv` or any other file.

## 7. Start the stash server again

If you have a `launchctl` name, use the same `LABEL`:

```sh
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/LABEL.plist
```

If you have no name:

```sh
nohup stash serve >> ~/.stash/stash.log 2>&1 &
```

Check that it runs:

```sh
curl -s http://127.0.0.1:8555/v1/health
```

The answer must be `{"ok":true}`.

## 8. Remove old token lines

Find old `STASH_TOKEN` lines:

```sh
grep -n "STASH_TOKEN" ~/.zshrc ~/.zshenv ~/.bash_profile ~/.profile 2>/dev/null
```

Open each file it names and delete each `export STASH_TOKEN=...` line. Then open a new Terminal window. Agents need no token now. stash finds its own.

## 9. Check that it works

```sh
stash list
stash run -- sh -c 'echo "stash run works"'
```

`stash list` shows each secret and its path: `proxy`, `aws` or `hand-over`.

If setup moved an AWS profile, test it. Use the profile name from setup in place of `PROFILE`:

```sh
aws --profile PROFILE sts get-caller-identity
```

It must print your AWS user. It must not print an error.

## 10. Restart what uses stash

- Claude Code or Codex sessions: quit and open them again. Their tools that use stash restart with them.
- A launch agent that runs `stash run`: `launchctl kickstart -k gui/$(id -u)/ITS_LABEL`.
- Anything you started by hand with `stash run`: stop it and start it again.

A stash server restart always ends these programs' stand-in keys. After each server restart, restart them.

## 11. Fix scripts with a fixed API address

A script that sends an OpenAI, Anthropic or OpenRouter key to a fixed address now fails, because it holds a stand-in key. Find them:

```sh
grep -rln -e "api.openai.com" -e "api.anthropic.com" -e "openrouter.ai/api" ~/your-projects
```

In each script that runs through `stash run`, use the address that stash gives the program. For `OPENROUTER_API_KEY`, the address is in `OPENROUTER_API_KEY_BASE_URL`. Example:

```sh
stash run --secret OPENROUTER_API_KEY -- sh -c '
  export OPENAI_API_KEY="$OPENROUTER_API_KEY"
  export OPENAI_BASE_URL="$OPENROUTER_API_KEY_BASE_URL"
  exec node server.js'
```

## Owner tasks after the upgrade

Paste the owner token into one Terminal window only, for that task:

```sh
export STASH_TOKEN=stash_owner_...
stash set NAME          # change an existing secret
stash get NAME          # read a value
stash audit --limit 50
exit                    # close the window when you finish
```

Agents can add a new secret with `stash set NAME`. Only the owner can change one that exists.

Add an AWS profile by hand:

```sh
stash aws connect PROFILE --key-id KEY_ID_SECRET_NAME --secret-key SECRET_KEY_SECRET_NAME
```

## Lost or leaked owner token

```sh
launchctl bootout gui/$(id -u)/LABEL     # or: pkill -f "stash serve"
stash reset-owner
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/LABEL.plist     # or: nohup stash serve >> ~/.stash/stash.log 2>&1 &
```

Save the new token in your password manager. The old one stops working.

## Go back to 0.4

Use this only if 0.5 does not work for you:

```sh
launchctl bootout gui/$(id -u)/LABEL     # or: pkill -f "stash serve"
rm -rf ~/.stash && cp -R ~/.stash-backup-0.4 ~/.stash
OLD="$(which stash)"; cp ~/stash-0.4-binary "$OLD.new" && mv "$OLD.new" "$OLD"
[ -f ~/.aws/config.pre-stash-0.5 ] && cp ~/.aws/config.pre-stash-0.5 ~/.aws/config
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/LABEL.plist
```

Secrets that you added after the upgrade are not in the backup.
