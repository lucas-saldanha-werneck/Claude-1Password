#!/bin/bash
# install.sh — put op-env / op-store / secret-dialog on PATH, build the macOS dialog, create the template,
#              self-test the guard. Writes small wrapper scripts (not symlinks: Git Bash on Windows
#              turns symlinks into copies that go stale).
# Usage: bash install.sh [--prefix DIR] [--wrap-claude]   (default DIR: ~/.local/bin)
#   --wrap-claude  also installs ~/.local/opbin/claude, a wrapper that starts claude through op-env.
#                  Put ~/.local/opbin FIRST in PATH (the script prints the line). Plain `claude`,
#                  launchers that resolve `claude` via PATH, and `op-env claude` all keep working.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
PREFIX="$HOME/.local/bin"
WRAP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) [ -n "${2:-}" ] || { echo "install.sh: --prefix needs a directory"; exit 1; }; PREFIX="$2"; shift 2 ;;
    --wrap-claude) WRAP=1; shift ;;
    *) echo "install.sh: unknown option $1"; exit 1 ;;
  esac
done
mkdir -p "$PREFIX"

ok()   { printf '  ok    %s\n' "$*"; }
warn() { printf '  warn  %s\n' "$*"; }
fail() { printf '  FAIL  %s\n' "$*"; }

echo "Claude-1Password install"
chmod +x "$HERE"/bin/op-env "$HERE"/bin/op-store "$HERE"/bin/secret-dialog "$HERE"/bin/secret-dialog-gtk.py

# 1. macOS: build the native dialog (needs Xcode or Command Line Tools)
if [ "$(uname -s)" = Darwin ]; then
  if command -v swiftc >/dev/null 2>&1; then
    LOG=$(mktemp)
    if swiftc -O -o "$HERE/bin/secret-dialog-macos" "$HERE/src/secret-dialog-macos.swift" 2>"$LOG"; then
      ok "built bin/secret-dialog-macos (native dialog with eye)"
    else
      warn "swiftc failed ($(head -1 "$LOG")); falling back to AppleScript (no eye)"
    fi
    rm -f "$LOG"
  else
    warn "swiftc not found: xcode-select --install  — falling back to AppleScript (no eye)"
  fi
fi

# 2. wrappers on PATH. Remove any existing entry FIRST: if it is a symlink into the repo, writing
#    through it would overwrite the real script (this happened once; never again).
for t in op-env op-store secret-dialog; do
  [ "$(cd "$PREFIX" && pwd)" = "$HERE/bin" ] && { fail "--prefix must not be the repo's bin directory"; exit 1; }
  rm -f "$PREFIX/$t"
  printf '#!/bin/bash\nexec "%s/bin/%s" "$@"\n' "$HERE" "$t" > "$PREFIX/$t" && chmod +x "$PREFIX/$t" && ok "$PREFIX/$t -> $HERE/bin/$t"
done

# 2b. optional claude wrapper (its own directory, so it can sit before ~/.local/bin in PATH)
if [ "$WRAP" = 1 ]; then
  OPBIN="$HOME/.local/opbin"; mkdir -p "$OPBIN"; rm -f "$OPBIN/claude"
  cp "$HERE/bin/claude-wrapper" "$OPBIN/claude" && chmod +x "$OPBIN/claude" && ok "$OPBIN/claude (wrapper: claude → op-env → real claude)"
  case ":$PATH:" in *":$OPBIN:"*) ok "$OPBIN is in PATH" ;; *) warn "add to your shell profile, AFTER any line that sets PATH:  export PATH=\"\$HOME/.local/opbin:\$PATH\"" ;; esac
fi

# 3. template
TPL="$HOME/.claude/.env.tpl"
if [ -f "$TPL" ]; then
  ok "template exists: $TPL"
else
  mkdir -p "$HOME/.claude" && cp "$HERE/templates/env.tpl.example" "$TPL" && ok "created $TPL (edit it: op:// references only)"
fi

# 4. checks
case ":$PATH:" in *":$PREFIX:"*) ok "$PREFIX is in PATH" ;; *) warn "$PREFIX is NOT in PATH — add it to your shell profile" ;; esac
PY=$(command -v python3 || command -v python || true)
if [ -n "$PY" ]; then
  if printf '{"tool_input":{"command":"op read op://x/y/z"}}' | "$PY" "$HERE/hooks/guard.py" bash 2>/dev/null; then
    fail "guard self-test: 'op read' was NOT blocked (python: $PY)"
  else
    ok "guard self-test passed ($PY)"
  fi
else
  warn "python3 not found: the hooks will fail OPEN (nothing blocked) until Python is installed"
fi
if command -v op >/dev/null 2>&1; then
  ok "op $(op --version)"
  if op vault list >/dev/null 2>&1; then ok "op is connected to the 1Password app"
  else warn "op not connected: 1Password app > Settings > Developer > 'Integrate with 1Password CLI', then run: op-env --check"; fi
else
  warn "op not installed: macOS 'brew install --cask 1password-cli' | others: https://developer.1password.com/docs/cli/get-started/"
fi
echo
echo "Hooks come only with the plugin:  claude plugin marketplace add lucas-saldanha-werneck/Claude-1Password && claude plugin install op-secrets@op-secrets"
echo "Next:  op-env --check      then      op-env claude"
