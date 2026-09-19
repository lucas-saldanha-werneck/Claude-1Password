# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions: [Semantic Versioning](https://semver.org/). Release notes and downloadable assets: [GitHub Releases](https://github.com/lucas-saldanha-werneck/Claude-1Password/releases).

## [Unreleased]

## [0.4.2] - 2026-09-18

### Fixed
- `op-store` saved every item with an EMPTY value since 0.3.0 (2026-09-11), and still printed `OK`. The python
  helper that builds the item JSON was started as `python3 - <<'PY'`: the heredoc took over stdin, so the
  username and the value piped in from the dialog never reached it. The helper now takes its code through
  `-c` and reads the data from the pipe, refuses to build an item with an empty value, and the final check
  fails loudly when the field is missing **or empty** in 1Password.
  **If you saved anything with `op-store` between 0.3.0 and 0.4.1, open those items in the 1Password app:
  the field is blank. Run `op-store --update <title>` to fill it.**
- `op-store --update` wiped the other fields of the item (username, notes…): `op item edit` with a JSON
  template replaces the whole field list. It now fetches the current item (through a pipe, never printed),
  changes only the target field and sends the rest back unchanged.
- `op-store --update --field password` on a Login item added a second, empty `password` field instead of
  replacing the real one (the field had no `purpose`). A field named `password` now always carries
  `purpose: PASSWORD`. If you have an item with two `password` fields, delete the empty one in the app.
- macOS dialog: ⌘V / ⌘C / ⌘X / ⌘A did nothing in the field (only typing or right-click → Paste worked).
  An AppKit app without an Edit menu has no key equivalents; the dialog now installs a minimal one.
- `tests/run.sh`: end-to-end test of `op-store --login` and `--update` with a fake dialog and a fake `op`,
  asserting that the value the dialog returns is the value `op` receives and that `--update` keeps the
  other fields.

## [0.4.1] - 2026-09-18

### Added
- `op-env --check` prints a `macOS:` line when the terminal app has no Full Disk Access. On macOS 26 that is
  the reason "«iTerm» would like to access data from other apps" keeps popping up for `op`: the CLI reaches the
  desktop app through a socket inside 1Password's group container, and the App Data answer is kept only per
  terminal session and program. The probe (`head -c 1` on TCC.db) makes no privacy request of its own.

### Changed
- README and skill Troubleshooting: the App Data popup above, and `op-env` loading 0 keys when two 1Password
  items share a title ("More than one item matches") — delete the duplicate or reference the item by ID.

## [0.4.0] - 2026-09-11

### Changed (breaking)
- Plugin id renamed from `claude-1password` to `op-secrets` (marketplace submission rules: no brand names in the plugin name). Install: `claude plugin install op-secrets@op-secrets`. The repository name is unchanged.

### Added
- `install.sh --wrap-claude`: installs `~/.local/opbin/claude`, a wrapper so plain `claude` starts through `op-env` (loop-safe via `OP_ENV_LOADED=1`).
- `op-env --strict`: refuse to run when the secrets cannot be loaded.

### Changed
- `op-env` runs the command without secrets (with a loud warning) when the template is empty or 1Password is locked; `--strict` restores the old refusal.
- `op-env` exports `OP_ENV_LOADED=1` into the launched command.

### Notes
- Windows (PowerShell/WinForms) and Linux (kdialog, GTK4) dialog backends are written but not yet verified on real machines. Reports welcome.

## [0.3.0] - 2026-09-11

Fixes from a Codex review and an adversarial review, plus the demo.

### Security
- `op-store`: the value now reaches `op` as a JSON item through a pipe. It is never on the command line and never in the environment, so `ps` cannot show it. Tracing (`set +xv`) is switched off inside all scripts.
- `secret-dialog`: the AppleScript fallback receives title/message as arguments instead of interpolating them into script source (no AppleScript injection through a crafted title).
- `op-env`: removes `OP_SERVICE_ACCOUNT_TOKEN` from the launched session (`OP_ENV_KEEP_SA=1` keeps it).
- Guard: no per-command override the model can type (`ALLOW_SECRET=1` removed); writes into the guard itself or into a settings file that disables it are blocked.

### Added
- Guard on `Read`, `Grep` and `Glob` for secret files by path (`.env*`, `credentials`, `.netrc`, `.npmrc`, private keys, `hosts.yml`…), and the same path check inside Bash commands (`git show HEAD:.env`, `sed "" .env`…).
- Guard on `MultiEdit` and `NotebookEdit`.
- More leak patterns: unanchored `op read`/`op run`/`op inject`, `set`/`export -p`/`declare -x`, `/proc/*/environ`, `os.environ`, `process.env`, `printf`/`echo` of secret variables, `secret-dialog` called directly, `SHELLOPTS=xtrace`.
- More token formats: Hugging Face, Doppler, Stripe, SendGrid, Telegram, passwords inside URLs.
- `op-env --check` prints `op`'s own error when a reference does not resolve.
- `install.sh` self-tests the guard and warns when Python is missing.
- `tests/run.sh`: 119 cases, a "known gaps" section that documents bypasses honestly, and smoke tests.
- `demo/`: rendered demo GIF and MP4, source page and render script.
- `CHANGELOG.md`.

### Changed
- `op-env` uses a NUL-delimited transport, so multi-line values survive; the template is validated (identifiers only, values must start with `op://`); CRLF templates are tolerated.
- `install.sh` writes wrapper scripts instead of symlinks (Git Bash on Windows turns symlinks into copies) and removes any existing entry before writing.
- Hooks run through `sh -c` and fall back from `python3` to `python`.
- Stop hook: sentence-based; ignores negations and messages that point to the dialog; catches "what is your API key?".
- Prompt guard: left boundary on token patterns, so `desk-lamp-with-usb-charging-port` and URLs are not flagged.
- Linux: `zenity` shows the message; `timeout` falls back to `gtimeout`; GTK4 dialog is non-unique (a second dialog no longer exits as cancelled).
- Windows: PowerShell runs with `-STA`; output is UTF-8 bytes.
- README and SKILL: the security model says plainly that the guard is a filter, not a wall; hooks come only with the plugin install.

### Fixed
- `op-store`: bash 3.2 could not parse the field-name regex; wrong vault now fails with a clear message; `op` errors are shown only when they do not contain the value.
- `secret-dialog`/`op-store`: relative symlink targets resolve correctly.
- Block messages never include fragments of the detected token.

## [0.2.0] - 2026-09-11

### Added
- Guard hooks (`hooks/guard.py`, `hooks/hooks.json`): `UserPromptSubmit` erases pasted secrets before Claude sees them; `PreToolUse` on Bash and Write/Edit blocks leaking commands and literal secrets in files; `Stop` sends Claude back when it asks the user to paste a secret.
- `tests/run.sh` with 41 hook cases.

## [0.1.0] - 2026-09-11

### Added
- `op-env`: resolve `op://` references from `~/.claude/.env.tpl` once and `exec` a command with the TTY preserved.
- `op-store`: store a secret through a native dialog; `--login`, `--update`, `--field`, `--vault`.
- `secret-dialog`: native dialogs with a reveal toggle — macOS (Swift), Windows (PowerShell/WinForms), Linux KDE (`kdialog`) and GNOME (GTK4); AppleScript, zenity and `read -s` fallbacks.
- Claude Code skill `1password` with the rules.
- Plugin manifest and marketplace file; `install.sh`; MIT license.

[Unreleased]: https://github.com/lucas-saldanha-werneck/Claude-1Password/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/lucas-saldanha-werneck/Claude-1Password/releases/tag/v0.4.0
[0.3.0]: https://github.com/lucas-saldanha-werneck/Claude-1Password/releases/tag/v0.3.0
[0.2.0]: https://github.com/lucas-saldanha-werneck/Claude-1Password/commit/35aa4be
[0.1.0]: https://github.com/lucas-saldanha-werneck/Claude-1Password/commit/88bc2ad
