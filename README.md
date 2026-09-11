# Claude-1Password

1Password for [Claude Code](https://claude.com/claude-code), done so that secrets **never** enter the
chat, the transcript, the command line or your shell history.

Three small tools plus a Claude Code skill that teaches Claude to use them:

| Tool | Job |
|---|---|
| **`op-store`** | Claude runs it; a **native dialog** opens *outside Claude's view*. You paste the key, click the **eye** to double-check it, press OK. It lands in 1Password. Claude only sees `OK op://Claude/Apify/credential`. |
| **`op-env`** | `op-env claude` resolves every `op://` reference in `~/.claude/.env.tpl` with **one** biometric prompt, exports them, and `exec`s Claude Code with the TTY intact. Every tool, hook, script and MCP server inherits the variables. Nothing on disk. |
| **`secret-dialog`** | The dialog. Native on each OS, with a reveal toggle: macOS (Swift), Windows (PowerShell/WinForms), Linux KDE (`kdialog`) and GNOME (GTK4 `PasswordEntry`). Fallbacks: AppleScript, zenity, `read -s`. |

```
$ op-store Apify          # dialog opens → paste → eye → OK
OK op://Claude/Apify/credential

$ echo 'APIFY_TOKEN=op://Claude/Apify/credential' >> ~/.claude/.env.tpl
$ op-env claude           # Touch ID once; $APIFY_TOKEN is now available to everything Claude runs
```

## The guard hooks (installed with the plugin)

Rules in a skill are advice. Hooks are enforcement. `hooks/guard.py` runs on four events:

| Event | What it catches | What happens |
|---|---|---|
| `UserPromptSubmit` | **You** paste something that looks like a secret (known token formats, or `password:`/`token=` followed by a value) | The prompt is blocked **and erased before Claude sees it**. You get a note: use `op-store`. Prefix the message with `#allow-secret` to send anyway. |
| `PreToolUse` Bash | Claude runs `op read`, `op item get --reveal`, `printenv`, `echo $TOKEN`, `cat .env*`, `bash -x op-store`, `op item create credential=...`, or any command with a literal secret | Blocked. Claude is told to use `$VAR` from `op-env` or `op-store`. Prefix the command with `ALLOW_SECRET=1 ` to override. |
| `PreToolUse` Write/Edit | Claude writes a literal secret into a file | Blocked. Use `op://` or `${VAR}`. |
| `Stop` | Claude's last message asks you to *paste / send / cole / digite* a key, token or password | Claude is sent back to do it right: run `op-store`. |

Fail-open: if `python3` is missing or the script errors, nothing is blocked. Disable with `CLAUDE_1PASSWORD_GUARD=off`.
Run `bash tests/run.sh` to see the 41 cases.

## Why not just `op run -- claude`?

The child of `op run` gets no TTY, so Claude Code drops into non-interactive `--print` mode.
`op-env` resolves first, then `exec`s, so the terminal is preserved. And per-command `op read`
inside a session means a biometric prompt on every Bash call. Both problems are documented by the
community; this repo packages the fixes.

## Install

Requirements: [1Password CLI](https://developer.1password.com/docs/cli/get-started/) (`op` ≥ 2.x)
and the 1Password desktop app with **Settings → Developer → "Integrate with 1Password CLI"** turned on
(Touch ID / Windows Hello / PolKit). Or a [service account](https://developer.1password.com/docs/service-accounts/)
token in `OP_SERVICE_ACCOUNT_TOKEN`.

```bash
git clone https://github.com/lucas-saldanha-werneck/Claude-1Password.git
cd Claude-1Password
bash install.sh          # links op-env / op-store / secret-dialog into ~/.local/bin,
                         # builds the macOS dialog (needs swiftc), creates ~/.claude/.env.tpl
op-env --check
```

Install the skill so Claude knows the rules (never ask for secrets in chat, use `op-store`, etc.):

```bash
claude plugin marketplace add lucas-saldanha-werneck/Claude-1Password
claude plugin install claude-1password@claude-1password
```
or copy `skills/1password/` into `~/.claude/skills/`.

## Usage

```bash
op-store Apify                          # API Credential item, field `credential`, vault Claude
op-store --login UniFi --url https://192.168.0.1     # Login item: username (visible) + password (hidden)
op-store --update Apify                 # replace the value
op-store --vault Private --field password "Some item"

op-env claude                           # start Claude Code with the secrets
op-env claude --resume <id>             # any arguments pass through
op-env ./deploy.sh                      # any command, not only claude
op-env --check                          # diagnose
op-env --list                           # key names only
```

`~/.claude/.env.tpl` holds references only (safe to back up, never a value):
```
APIFY_TOKEN=op://Claude/Apify/credential
GITHUB_TOKEN=op://Claude/GitHub PAT/credential
```

MCP servers read the inherited variables with `${VAR}` in `.mcp.json`:
```json
{ "mcpServers": { "apify": { "command": "npx", "args": ["-y", "@apify/actors-mcp-server"],
  "env": { "APIFY_TOKEN": "${APIFY_TOKEN}" } } } }
```
HTTP MCP servers with a bearer token (must be added with `claude mcp add-json`):
```json
{ "type": "http", "url": "https://api.example.com/mcp",
  "headersHelper": "printf '{\"Authorization\": \"Bearer %s\"}' \"$(op read 'op://Claude/Example/credential')\"" }
```

## Platform status

| OS | Dialog backend | Eye | Status |
|---|---|---|---|
| macOS 13+ | Swift `NSAlert` + `NSSecureTextField` | yes | **tested** |
| macOS (no Xcode) | AppleScript `display dialog … with hidden answer` | no | tested |
| Windows 10/11 (Git Bash / WSL) | PowerShell + WinForms | yes | untested, please report |
| Linux KDE (KF ≥ 5.84) | `kdialog --password` | yes (built in) | untested, please report |
| Linux GNOME | GTK4 `Gtk.PasswordEntry` (`python3-gi`); GTK3 fallback | yes | untested, please report |
| Linux other | `zenity --password` | no | untested |
| any TTY | `read -s` | no | tested |

## Security model, honestly

- **The vault does not isolate.** With the desktop-app integration, `op` can read every vault of your
  account while the app is unlocked. A `Claude` vault is tidy, not a boundary. For a real boundary,
  create a service account limited to that vault and turn the app integration off. (Verified: a service
  account scoped to `Claude` cannot even list the other vaults.)
- **Injected env vars are readable by the process.** `op-env` keeps secrets off disk and out of the
  transcript, but a prompt-injected agent could still `printenv`. The skill forbids printing environments;
  it is a rule, not a wall. If you need a wall, look at credential proxies (agent holds a placeholder,
  proxy injects the real value).
- **`op://` references leak names** of vaults, items and fields. Keep those boring.
- Claude Code's own OAuth token is stored in the OS keychain readable by same-user processes
  ([Silverfort, 2026-07](https://www.silverfort.com/blog/skipping-the-lock-a-claude-code-cli-weakness-lets-any-macos-process-read-stored-credentials)). Not something this repo can fix.

## Credits

- The `op-env` "resolve once, then exec" pattern: [DAESA24's gist](https://gist.github.com/DAESA24/dc26fa5b63fcd6b4c688772c9d0eb5ca).
- The hidden-dialog store pattern: [mackinleysmith/1pass-secrets](https://github.com/mackinleysmith/1pass-secrets).
- The "never type secrets into Claude Code" rule and Terminal-launch flow: [kcmadden/claude-code-1password-skill](https://github.com/kcmadden/claude-code-1password-skill).
- 1Password docs: [CLI app integration](https://developer.1password.com/docs/cli/app-integration/), [secret references](https://developer.1password.com/docs/cli/secret-references/), [service accounts](https://developer.1password.com/docs/service-accounts/).

MIT. Not affiliated with 1Password or Anthropic.
