#!/bin/bash
# install.sh — link the tools into ~/.local/bin, build the macOS dialog, create the template.
# Usage: bash install.sh [--prefix DIR]   (default DIR: ~/.local/bin)
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
PREFIX="$HOME/.local/bin"
[ "${1:-}" = "--prefix" ] && PREFIX="$2"
mkdir -p "$PREFIX"

ok()   { printf '  ok    %s\n' "$*"; }
warn() { printf '  warn  %s\n' "$*"; }
fail() { printf '  FAIL  %s\n' "$*"; }

echo "Claude-1Password install"
chmod +x "$HERE"/bin/op-env "$HERE"/bin/op-store "$HERE"/bin/secret-dialog "$HERE"/bin/secret-dialog-gtk.py

# 1. macOS: build the native dialog (needs Xcode or Command Line Tools)
if [ "$(uname -s)" = Darwin ]; then
  if command -v swiftc >/dev/null 2>&1; then
    if swiftc -O -o "$HERE/bin/secret-dialog-macos" "$HERE/src/secret-dialog-macos.swift" 2>/tmp/claude-1password-swift.log; then
      ok "built bin/secret-dialog-macos (native dialog with eye)"
    else
      warn "swiftc failed (see /tmp/claude-1password-swift.log); falling back to osascript (no eye)"
    fi
  else
    warn "swiftc not found: xcode-select --install  — falling back to osascript (no eye)"
  fi
fi

# 2. link the commands
for t in op-env op-store secret-dialog; do
  ln -sf "$HERE/bin/$t" "$PREFIX/$t" && ok "$PREFIX/$t -> bin/$t"
done

# 3. template
TPL="$HOME/.claude/.env.tpl"
if [ -f "$TPL" ]; then
  ok "template exists: $TPL"
else
  mkdir -p "$HOME/.claude" && cp "$HERE/templates/env.tpl.example" "$TPL" && ok "created $TPL (edit it: op:// references only)"
fi

# 4. checks
case ":$PATH:" in *":$PREFIX:"*) ok "$PREFIX is in PATH" ;; *) warn "$PREFIX is NOT in PATH — add it to your shell profile" ;; esac
if command -v op >/dev/null 2>&1; then
  ok "op $(op --version)"
  if op vault list >/dev/null 2>&1; then ok "op is connected to the 1Password app"
  else warn "op not connected: 1Password app > Settings > Developer > 'Integrate with 1Password CLI', then run: op-env --check"; fi
else
  warn "op not installed: macOS 'brew install --cask 1password-cli' | others: https://developer.1password.com/docs/cli/get-started/"
fi
echo
echo "Next:  op-env --check      then      op-env claude"
