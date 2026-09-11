---
name: 1password
description: >
  Use 1Password with Claude Code without secrets ever entering the chat, the transcript, the
  command line or shell history. Trigger when the user wants to store an API key, token, password
  or credential; when a tool, MCP server, hook or script needs a secret; when the user mentions
  1Password, `op`, `op://`, secret references, .env files with secrets, "where do I put my key",
  or asks how to launch Claude Code with secrets loaded. Provides: `op-store` (native hidden
  dialog with an eye/reveal toggle → straight into 1Password), `op-env` (launch any command with
  secrets injected, TTY preserved, one biometric prompt) and `secret-dialog`.
---

# 1Password for Claude Code

## The one rule

**Never ask the user to paste a secret into the chat.** Anything typed in the chat or shown in a
tool result is in the transcript forever. Instead run `op-store <title>`: a native dialog opens
outside Claude's view, the user pastes there, the value goes straight into 1Password, and only the
`op://` reference comes back.

Also never: print a secret value, `op read` inside every Bash call (biometric prompt fatigue),
`source <(op run ... env)` or `eval` (values with shell metacharacters execute as code),
`bash -x` any script that handles a value (the trace prints it).

## The guard hooks enforce this

When installed as a plugin, `hooks/guard.py` blocks: secrets pasted by the user (erased before you
see them), `op read` / `op item get --reveal` / `printenv` / `echo $TOKEN` / `cat .env*` /
`op item create ...=value` in Bash, literal secrets in Write/Edit, and any final message of yours
that asks the user to paste a secret. If a hook blocks you, do what its message says: run
`op-store <title>` and use the `op://` reference or `$VAR`. Do not look for a way around it.

## Commands (installed by `install.sh` into `~/.local/bin`)

| Command | What it does |
|---|---|
| `op-store <title>` | Opens the native dialog (hidden field + eye). Saves an *API Credential* item, field `credential`, in vault `Claude`. Prints `OK op://Claude/<title>/credential`. |
| `op-store --login <title> [--url URL]` | Asks username (visible) then password (hidden). Saves a *Login* item. |
| `op-store --update <title>` | Replaces the value of an existing item. |
| `op-store --vault V --field F <title>` | Other vault / field name. |
| `op-env <command>` | Resolves every `op://` line of `~/.claude/.env.tpl` in ONE `op` call, exports them, then `exec`s the command. TTY preserved. Use `op-env claude` to start Claude Code. |
| `op-env --check` | Shows op version, template, account, and how many keys resolve. Run this first when anything fails. |
| `op-env --list` | Key names only, never values. |
| `secret-dialog "Title" "Message" [--visible] [--timeout S]` | The dialog itself. Prints the text. Exit 2 cancelled, 3 timeout, 4 empty, 5 no backend. |

## Workflows

**User wants to store a secret** (key, token, password):
1. Choose a short item title (e.g. `Apify`, `GitHub PAT`, `UniFi`).
2. Run `op-store <title>` (or `--login` for user+password). Tell the user a dialog opened and to paste there.
3. On `OK op://...`, append `VAR_NAME=op://...` to `~/.claude/.env.tpl` if a tool needs it as an env var.
4. Tell the user to restart Claude Code with `op-env claude` so the new variable is loaded.
   Never verify by printing the value; `op-store` already confirmed the field exists.

**A tool / script / hook needs a secret** and Claude was started with `op-env`:
the variable is already in the environment. Use `$VAR_NAME` in the command. Do not `op read` again.
If the variable is missing, check `op-env --list`, then ask the user to add it with `op-store`
and restart with `op-env claude`.

**MCP server needs a token** (`.mcp.json`): use `${VAR_NAME}` expansion, inherited from `op-env`:
```json
{ "mcpServers": { "x": { "command": "npx", "args": ["-y", "x-mcp"], "env": { "X_TOKEN": "${X_TOKEN}" } } } }
```
HTTP servers with a bearer header: `claude mcp add-json` with a `headersHelper` that runs
`op read` once at connect time (see README).

**One-off value outside a session**: `op read "op://Claude/Item/credential"` — fine in the
user's own terminal, avoid inside Claude's Bash tool (each call is a new shell → new prompt).

## Setup check (run before the first use)

```bash
op-env --check
```
- `op not found` → macOS `brew install --cask 1password-cli`; other OS: https://developer.1password.com/docs/cli/get-started/
- `NOT connected` → 1Password app > Settings > Developer > "Integrate with 1Password CLI"
  (Touch ID / Windows Hello / PolKit). Or export `OP_SERVICE_ACCOUNT_TOKEN` (no app needed, scoped to chosen vaults).
- `resolved: N of M` with N < M → a reference in the template is wrong (vault/item/field name).

## Security model (tell the user when relevant)

- With the desktop-app integration, `op` can read **every vault** of the account while the app is
  unlocked, not only `Claude`. The vault is organisation, not isolation. For real isolation use a
  **service account** scoped to one vault (`op service-account create name --vault Claude:read_items`)
  and turn the app integration off.
- Injected env vars protect the disk and the transcript. A process can still `printenv`. Do not
  print environments; do not run `env`/`printenv`/`set` without filtering.
- `op://` references reveal vault, item and field *names*. Keep them non-sensitive.
- Claude Code's own login token lives in the OS keychain and is readable by same-user processes
  (reported by Silverfort, 2026-07). Unrelated to 1Password; nothing here changes it.

## Troubleshooting

- Claude starts in `--print` mode / "No terminal detected": you used `op run -- claude`. Use `op-env claude`.
- `op whoami` says "account is not signed in" but everything works: known with app integration; ignore.
- Repeated biometric prompts: something calls `op` per command. Move the secret to the template and use `op-env`.
- MCP server fails after `/mcp` reconnect: reconnect spawns non-interactively, `op` cannot prompt. Prefer `${VAR}` from `op-env`.
- Dialog never appears (macOS): the binary `secret-dialog-macos` is missing → run `install.sh` (needs `swiftc`); falls back to AppleScript (no eye).
- Linux: KDE uses `kdialog --password` (eye built in, KDE Frameworks ≥ 5.84); GNOME uses GTK4 `Gtk.PasswordEntry` via `python3-gi`; else `zenity` (no eye); else `read -s` in a TTY.
- Windows: PowerShell + WinForms dialog. Claude Code runs in Git Bash; the scripts run there.
  Windows and Linux backends are not yet verified by the author.
