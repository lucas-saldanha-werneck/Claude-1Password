# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions: [Semantic Versioning](https://semver.org/). Release notes and downloadable assets: [GitHub Releases](https://github.com/lucas-saldanha-werneck/Claude-1Password/releases).

## [Unreleased]

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

[Unreleased]: https://github.com/lucas-saldanha-werneck/Claude-1Password/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/lucas-saldanha-werneck/Claude-1Password/releases/tag/v0.3.0
[0.2.0]: https://github.com/lucas-saldanha-werneck/Claude-1Password/commit/35aa4be
[0.1.0]: https://github.com/lucas-saldanha-werneck/Claude-1Password/commit/88bc2ad
