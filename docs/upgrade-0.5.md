# Upgrade stash to 0.5, step by step

Time: about 10 minutes. Do every step in your own terminal, on the computer that runs stash.
Most steps are the same on a Mac and on Linux or WSL. Where they differ, both are shown.
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
ps aux | grep "[s]tash serve"
```

Write down the path from `which stash`, for example `/usr/local/bin/stash` or `~/go/bin/stash`.

Then find out how stash starts.

Mac:

```sh
launchctl list | grep -i stash
```

If a line shows, write down the name in its last column. Below, that name is `LABEL`.

Linux or WSL:

```sh
systemctl --user list-unit-files 2>/dev/null | grep -i stash
```

If a line shows, write down its name, for example `stash.service`. Below, that name is `UNIT`.

If neither shows a line, you start stash by hand. Below, that is "by hand".

## 2. Back up

```sh
cp -R ~/.stash ~/.stash-backup-0.4
cp "$(which stash)" ~/stash-0.4-binary
[ -f ~/.aws/config ] && cp ~/.aws/config ~/.aws/config.pre-stash-0.5
```

## 3. Get the new version

stash 0.5 needs Go 1.21 or newer. Check with `go version`.

If Go is missing or older on a Mac, run `brew install go`.

If Go is missing or older on Linux or WSL, install the official build:

```sh
curl -LO https://go.dev/dl/go1.25.1.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.25.1.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
go version
```

Then:

```sh
mkdir -p /tmp/stash-new
GOBIN=/tmp/stash-new go install github.com/FatherMarz/stash@latest
/tmp/stash-new/stash version
```

The last line must say `0.5.0`.

## 4. Stop the stash server

Mac with `LABEL`: `launchctl bootout gui/$(id -u)/LABEL`

Linux or WSL with `UNIT`: `systemctl --user stop UNIT`

By hand: `pkill -f "stash serve"`

Check that it stopped. This line must print nothing:

```sh
ps aux | grep "[s]tash serve"
```

## 5. Put the new version in place

Copy the new file next to the old one, then rename it over the old one. A plain copy over the old file can fail or kill it.
If the old file is in a system folder like `/usr/local/bin`, put `sudo` in front of `cp` and `mv`.

```sh
OLD="$(which stash)"
cp /tmp/stash-new/stash "$OLD.new"
mv "$OLD.new" "$OLD"
hash -r
stash version
```

The last line must say `0.5.0`.

## 6. Run setup

```sh
stash setup
```

Setup prints how many secrets went to each path. It lists each AWS profile that it moved. Then it shows the owner token once.

Copy the owner token into your password manager now. Do not put it in `~/.bashrc`, `~/.zshrc` or any other file.

## 7. Start the stash server again

Mac with `LABEL`: `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/LABEL.plist`

Linux or WSL with `UNIT`: `systemctl --user start UNIT`

By hand: `nohup stash serve >> ~/.stash/stash.log 2>&1 &`

On WSL, a stash started by hand stops when WSL shuts down. Start it again after each restart of WSL.

Check that it runs:

```sh
curl -s http://127.0.0.1:8555/v1/health
```

The answer must be `{"ok":true}`.

## 8. Remove old token lines

Find old `STASH_TOKEN` lines:

```sh
grep -n "STASH_TOKEN" ~/.bashrc ~/.zshrc ~/.zshenv ~/.bash_profile ~/.profile 2>/dev/null
```

Open each file it names and delete each `export STASH_TOKEN=...` line. Then open a new terminal. Agents need no token now. stash finds its own.

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
- A service that runs `stash run`. On a Mac: `launchctl kickstart -k gui/$(id -u)/ITS_LABEL`. On Linux or WSL: `systemctl --user restart ITS_UNIT`.
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

Paste the owner token into one terminal only, for that task:

```sh
export STASH_TOKEN=stash_owner_...
stash set NAME          # change an existing secret
stash get NAME          # read a value
stash audit --limit 50
exit                    # close the terminal when you finish
```

Agents can add a new secret with `stash set NAME`. Only the owner can change one that exists.

Add an AWS profile by hand:

```sh
stash aws connect PROFILE --key-id KEY_ID_SECRET_NAME --secret-key SECRET_KEY_SECRET_NAME
```

## Lost or leaked owner token

Stop the server as in step 4. Then:

```sh
stash reset-owner
```

Start the server as in step 7.

Save the new token in your password manager. The old one stops working.

## Go back to 0.4

Use this only if 0.5 does not work for you:

Stop the server as in step 4. Then:

```sh
rm -rf ~/.stash && cp -R ~/.stash-backup-0.4 ~/.stash
OLD="$(which stash)"; cp ~/stash-0.4-binary "$OLD.new" && mv "$OLD.new" "$OLD"
[ -f ~/.aws/config.pre-stash-0.5 ] && cp ~/.aws/config.pre-stash-0.5 ~/.aws/config
```

Start the server as in step 7.

Secrets that you added after the upgrade are not in the backup.
