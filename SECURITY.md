# Security Policy

## Reporting a vulnerability

Please report it privately: open the repository's **Security** tab and choose **Report a vulnerability**
(https://github.com/lucas-saldanha-werneck/op-secrets/security/advisories/new). Please do not open a public issue for a
security problem.

## Supported versions

Only the latest release is supported. Fixes go into a new release.

## What op-secrets accesses

- Runs `op` (the 1Password CLI) to save and load secrets. With the desktop-app integration `op` can read every vault of your account while the app is unlocked, so a `Claude` vault is tidy, not a boundary (see "Security model, honestly" in the README).
- `op-env` and `op-store` read a service-account token from the macOS Keychain item `op-env-sa` whenever that item exists, and pass it to `op` in its environment. `op-env` removes it before it starts your command.
- `op-store` collects a value in a native dialog (Swift, AppleScript, kdialog, zenity, GTK, PowerShell or the terminal) and pipes it to `op` through stdin. It never goes on a command line.
- `op-env` puts the resolved secrets in the environment of the command it starts. With `op-env claude`, every command Claude runs inherits them. The hooks block the usual ways of printing them, but they are a filter, not a sandbox, so a value can still reach the transcript. `op-env` logs `op`'s error text (never values) to `~/Library/Logs/op-env.log`, or `~/.local/state/op-env/op-env.log` off macOS. `op-env --check` reads one byte of macOS's `TCC.db` to see whether your terminal has Full Disk Access.
- The hooks read your prompts and Claude's tool calls locally. The Stop hook also reads the session transcript file when Claude Code does not pass the last message.
- `install.sh` writes small wrappers into `~/.local/bin`, builds the macOS dialog, and creates `~/.claude/.env.tpl`. With `--wrap-claude` it also installs `~/.local/opbin/claude`, which starts `claude` through `op-env` once that folder comes first in your PATH.
- No network requests of its own beyond what `op` does.
