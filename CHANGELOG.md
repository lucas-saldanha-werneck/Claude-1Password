# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions: [Semantic Versioning](https://semver.org/). Release notes and downloadable assets: [GitHub Releases](https://github.com/lucas-saldanha-werneck/op-secrets/releases).

## [0.7.0] - 2026-11-13

### Changed
- Renamed the skill to `op-secrets` (the old name `1password` broke the skill schema). The `op-env`, `op-store` and `secret-dialog` commands keep their names.
- Skill frontmatter has `version` and `tags`; the skill has Purpose, Prerequisites and Limitations sections; the description is in the third person.
- The README shows only the new demo (the old `demo/demo.gif` image is gone from the page); demo video and badges in the README; adds SECURITY.md.

## [0.6.6] - 2026-11-13

### Changed
- Skill frontmatter has the author; the skill has Instructions and Examples sections; the plugin author matches the other plugins.

## [0.6.5] - 2026-11-12

### Fixed
- `claude-wrapper` found no real `claude` when `~/.local/bin/claude` did not exist (it used `command -v -a`,
  which bash does not have) and exited 127. It now uses `type -ap` and skips itself with `-ef`.
- `op-env`: one broken reference no longer drops every key. When the whole template fails, keys are resolved one
  by one; the warning names the keys that did not resolve.
- `op-env --strict` now also refuses a partial load (some keys missing), not only an empty one.
- `op-env` with an empty template no longer passes `OP_SERVICE_ACCOUNT_TOKEN` to the command.
- `op-env` failure log: `~/Library/Logs` on macOS, `$XDG_STATE_HOME/op-env` (`~/.local/state/op-env`) elsewhere;
  the folder is created and a failed write prints nothing.
- `op-store`: a read-only Keychain service-account token (passes the `op vault get` test, fails to write) no longer
  makes every save fail: op-store retries once through the 1Password app. Saves of the same item take a lock,
  so two `--update` runs cannot undo each other.
- Setup recipe: the service-account token reaches `security` through stdin (`security -i`), never its argv, and
  the token is created with `read_items,write_items` everywhere (the `op-env` comment said `read_items`).
- `install.sh` writes the repo path shell-quoted (`%q`) into the PATH wrappers.
- Hooks: a `python` that is Python 2 is refused with a warning (exit 1, shown to the user) instead of failing silently.
- Guard:
  - blocks a recursive content search for a key name that would meet `.env` files (`grep -rn API_KEY .`,
    `rg --hidden ...`, Grep with `output_mode: content` over a folder or with a glob like `.env*`); listing files
    (`-l`, files_with_matches), `--include='*.py'` and `--exclude='.env*'` still pass;
  - blocks `security find-generic-password|find-internet-password -w/-g` printed to the screen (capturing it in a
    variable or piping it into a non-printing command still passes);
  - blocks printing one secret variable from a script (`print(os.environ['X_TOKEN'])`, `console.log(process.env.X_KEY)`)
    and `curl -v/--trace` or `wget --debug` with a secret variable or under `op-env`;
  - block messages name the keyword only, never the first characters of the value.

## [0.6.4] - 2026-11-11

### Fixed
- Guard: `op-env` is now unwrapped like `sudo`/`env`/`timeout` (including `--tpl X`, `--strict`, `--`), so the
  command it runs is judged. `op-env printenv`, `op-env -- env`, `op-env printenv <ANY_NAME>` and
  `op-env sh -c 'export -p'` are blocked; `op-env -- sh -c '[ -n "$VAR" ] && echo set'` still passes.

## [0.6.3] - 2026-11-11

### Changed
- Points to the catalog repo's new name, `lucas-tools`.

## [0.6.2] - 2026-11-11

### Changed
- Catalog renamed to `lucas-tools`: install with `op-secrets@lucas-tools`.

## [0.6.1] - 2026-11-09

### Added
- `op-env --meta "<item>" [vault]`: shows title, vault, category, version, created/updated dates and
  field names of one item, never values. Answers "did my edit in the app reach 1Password?" without
  `op item get`, which the guard blocks.
- `op-env --list` works without the `op` CLI (it only reads the template).

### Changed
- The repository is now `lucas-saldanha-werneck/op-secrets` (was `Claude-1Password`; GitHub redirects the old URL).
- The README installs the plugin from the catalog (`op-secrets@lucas-plugins`); the repo's own
  marketplace still works for existing installs.
- Short plugin description.
- CI runs the tests on Linux, macOS and Windows.

### Fixed
- `op-env` retries twice when it loads 0 keys (seen 2026-10-02: sessions opened in the same minute got
  nothing while `op-env --check` passed seconds later) and logs op's error to `~/Library/Logs/op-env.log`.
- Windows: `op-store --update` gets the current item through bash.

## [0.6.0] - 2026-09-26

### Added
- Headless mode on macOS: a 1Password **service account** token stored in the Keychain (item `op-env-sa`)
  is picked up by `op-env` and `op-store`. Secrets in that vault load and save with **no biometric prompt**,
  so sessions started while you are away from the Mac (Remote Control) get their keys. Vaults the service
  account cannot see (Private/Personal) keep using the app integration and Touch ID as before.
  One-time setup (the token never reaches the screen):
  `t=$(op service-account create "Claude Code op-env" --vault Claude:read_items,write_items --raw) && printf 'add-generic-password -U -a %s -s op-env-sa -T /usr/bin/security -w %s\n' "$USER" "$t" | security -i; unset t`
  (updated in 0.6.5: the token reaches `security` through stdin, not its argv)
  - `OP_ENV_SA_KEYCHAIN=<name>` picks another Keychain item; `OP_ENV_SA_KEYCHAIN=off` disables the lookup.
  - `op-env --check` shows `account: service account (keychain op-env-sa) — vaults: ...`.
  - `op-store` uses the token only when it can see the target vault (`op vault get`), else falls back.
- Tip: reference items by ID (`op://<vault id>/<item id>/<field>`) — 1 read instead of 3 per reference
  (1Password rate limits: 1,000 reads/day on individual and family accounts). Measured: a 22-key load cost ~2 reads.

## [0.5.0] - 2026-09-24

### Changed
- The guard judges a Bash command by what it does, not by the words in it. Replayed against every block from
  2026-09-11 to 09-24 (99 unique): 77 were false alarms and are now allowed; the 22 real catches still block.
  - Quoted search patterns (`grep -E 'op read|op run'`), heredocs that only write a file, and `jq` filters
    (`.env`, `.key`) are data, not commands. Quotes run by `bash -c`, `ssh host` or `eval` are still checked.
  - Secret files may be listed, moved, copied, counted, sourced, or read for variable NAMES only
    (`grep -o '^[A-Z_]*'`, `grep -c`, `cut -d= -f1`, `sed 's/=.*//'`, `awk -F= '{print $1}'`, `| wc`,
    `VAR=$(...)`). Printing values is still blocked. `.env.tpl.bak-*` and public CA bundles (`cacert.pem`) are not secret files.
  - `env | grep X` is allowed when a later stage masks the values; `printenv NAME` is allowed for names that
    do not look secret; `set`/`export -p` only match as real commands. `2>/dev/null` no longer counts as hiding output.
  - Script dumps match only explicit whole-environment prints (`print(os.environ)`), not `os.environ["TMPDIR"]`.
  - `secret-dialog` blocks only when run, not when read or compiled. `op item edit` allows username/url fields and `--help`.
- Literal-secret detection skips code: `process.env.X`, `config.a.b`, `obj.camelCase`, function calls, regex
  fragments, `ENV_VAR_NAME` placeholders, `user:${TOK}@` URLs, and a private-key header without a key body.
- The stop check matches whole words only ("computador", "TypeSafe", "puts", "1Password", "43k tokens" were
  false hits), ignores code and quoted text, and no longer treats a bare "your" as a request.

### Security
- New side doors closed while loosening: `find -exec`, `tar -O`/`unzip -p`, `cp .env /dev/stdout`, `grep -o '.*'`,
  a second `sed -e` script, `cat <<EOF | sh`, `set -x` + `source .env`, `declare -p SECRET`. 204 tests pass.

## [0.4.2] - 2026-09-19

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
- `CHANGELOG.md`.

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

[0.6.0]: https://github.com/lucas-saldanha-werneck/op-secrets/releases/tag/v0.6.0
[0.5.0]: https://github.com/lucas-saldanha-werneck/op-secrets/releases/tag/v0.5.0
[0.4.1]: https://github.com/lucas-saldanha-werneck/op-secrets/releases/tag/v0.4.1
[0.4.0]: https://github.com/lucas-saldanha-werneck/op-secrets/releases/tag/v0.4.0
[0.3.0]: https://github.com/lucas-saldanha-werneck/op-secrets/releases/tag/v0.3.0
[0.2.0]: https://github.com/lucas-saldanha-werneck/op-secrets/commit/35aa4be
[0.1.0]: https://github.com/lucas-saldanha-werneck/op-secrets/commit/88bc2ad
