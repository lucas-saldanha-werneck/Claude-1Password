#!/usr/bin/env python3
"""guard.py — Claude Code hooks that force secrets through 1Password (op-store / op-env).

Usage (from hooks.json):  python3 guard.py <event>     event = prompt | bash | write | stop
Reads the hook JSON on stdin. Fail-open: any internal error exits 0 (never blocks by accident).

  prompt  UserPromptSubmit  the USER pasted something that looks like a secret
                            → block + erase the prompt (Claude never sees it), tell the user to use op-store
  bash    PreToolUse Bash   Claude's command would print a secret or put a literal secret on the command line
                            → block, tell Claude to use $VAR from op-env or op-store
  write   PreToolUse Write|Edit  Claude would write a literal secret into a file → block
  stop    Stop              Claude just asked the user to paste a secret in chat → block, make Claude use op-store

Escape hatches:  prompt starting with "#allow-secret"; command starting with "ALLOW_SECRET=1 ";
                 env CLAUDE_1PASSWORD_GUARD=off disables everything.
"""
import json
import os
import re
import sys

# --- secret detector -----------------------------------------------------------------------------
# High-precision prefixes first (known token formats), then "keyword = long-token".
KNOWN = [
    r"sk-ant-[A-Za-z0-9_\-]{20,}",            # Anthropic
    r"sk-(?:proj-|live_|test_)?[A-Za-z0-9_\-]{20,}",  # OpenAI / Stripe
    r"gh[pousr]_[A-Za-z0-9]{30,}",            # GitHub classic tokens
    r"github_pat_[A-Za-z0-9_]{50,}",          # GitHub fine-grained
    r"ops_[A-Za-z0-9]{100,}",                 # 1Password service account
    r"xox[abprs]-[A-Za-z0-9\-]{20,}",         # Slack
    r"AKIA[0-9A-Z]{16}",                      # AWS access key id
    r"AIza[0-9A-Za-z_\-]{35}",                # Google API key
    r"ya29\.[A-Za-z0-9_\-]{40,}",             # Google OAuth
    r"glpat-[A-Za-z0-9_\-]{20}",              # GitLab
    r"npm_[A-Za-z0-9]{36}",                   # npm
    r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{30,}",  # PyPI
    r"apify_api_[A-Za-z0-9]{20,}",            # Apify
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----",
    r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",  # JWT
]
KEYWORD = r"(?:api[_\- ]?key|apikey|secret|token|password|passwd|senha|credential|client[_\- ]?secret|private[_\- ]?key|bearer)"
# keyword, then : or = or "is", then a 12+ char run with no spaces/quotes (symbols allowed: passwords have them)
KW_VALUE = re.compile(KEYWORD + r"[\"']?\s*(?:[:=]|is|:)\s*[\"']?([^\s\"'`]{12,})", re.I)
KNOWN_RE = re.compile("|".join(KNOWN))
# things that look like values but are references/placeholders, never block on these
SAFE = re.compile(r"^(?:op://|\$\{?[A-Z_]+\}?$|<[^>]+>$|YOUR_|xxx|\.\.\.|placeholder|example|changeme|dummy|test)", re.I)


def looks_like_secret(text: str) -> str:
    """Return a short reason if text contains something that looks like a real secret, else ''."""
    if not text:
        return ""
    m = KNOWN_RE.search(text)
    if m:
        return "a token in a known format (%s...)" % m.group(0)[:6]
    for m in KW_VALUE.finditer(text):
        val = m.group(1)
        if SAFE.match(val) or "op://" in text[max(0, m.start() - 8):m.end()]:
            continue
        if re.fullmatch(r"[A-Za-z]+", val):        # a plain word, e.g. "password is required"
            continue
        if re.search(r"\d", val) or re.search(r"[A-Z]", val) and re.search(r"[a-z]", val):
            return "a value after '%s'" % m.group(0)[:12].strip()
    return ""


# --- events ------------------------------------------------------------------------------------
def out(obj):
    sys.stdout.write(json.dumps(obj))
    sys.stdout.flush()


def ev_prompt(d):
    p = d.get("prompt", "") or ""
    if p.lstrip().startswith("#allow-secret"):
        return
    why = looks_like_secret(p)
    if why:
        out({"decision": "block",
             "reason": "Claude-1Password: your message looked like it contained a secret (%s). "
                       "It was NOT sent to Claude and was erased. Store it safely instead: tell Claude "
                       "\"store my <name> key\" and it will run `op-store <name>`, which opens a native dialog "
                       "outside the chat. To send anyway, start the message with #allow-secret" % why})


BASH_LEAKS = [
    (r"(?:^|[;&|]\s*)op\s+read\b", "`op read` prints the secret into the transcript. Use $VAR loaded by op-env, or op-store to save one."),
    (r"(?:^|[;&|]\s*)op\s+item\s+get\b.*(?:--reveal|--fields|--format)", "`op item get` with --reveal/--fields/--format prints secret values. Use $VAR from op-env."),
    (r"(?:^|[;&|]\s*)op\s+document\s+get\b", "`op document get` prints the document. Do not."),
    (r"(?:^|[;&|]\s*)(?:printenv|env)\s*(?:$|[;&|>])", "printing the whole environment leaks the secrets injected by op-env. Use `op-env --list` (names only)."),
    (r"(?:^|[;&|]\s*)printenv\s+[A-Z_]+", "printing a secret env var leaks it. Use it in a command instead: curl -H \"Authorization: Bearer $VAR\" ..."),
    (r"(?:^|[;&|]\s*)echo\s+[\"']?\$\{?[A-Z_]*(?:TOKEN|KEY|SECRET|PASS|PASSWORD|CREDENTIAL)[A-Z_]*\}?", "echoing a secret env var leaks it."),
    (r"(?:^|[;&|]\s*)(?:cat|less|head|tail|bat|grep\b[^|]*)\s+[^|;&]*\.env(?:\.[A-Za-z0-9_-]+)?\b", "reading a .env file puts its secrets in the transcript. Use op-env --list, or migrate it with op-store."),
    (r"bash\s+-x\s+\S*(?:op-store|op-env|secret-dialog)", "tracing op-store/op-env prints the secret. Never use -x on them."),
    (r"(?:^|[;&|]\s*)op\s+item\s+(?:create|edit)\b", "putting the value on the command line records it in the transcript. Use `op-store <title>` (native hidden dialog)."),
]


def ev_bash(d):
    cmd = (d.get("tool_input") or {}).get("command", "") or ""
    if cmd.startswith("ALLOW_SECRET=1 "):
        return
    for pat, msg in BASH_LEAKS:
        if re.search(pat, cmd, re.I | re.M):
            sys.stderr.write("Claude-1Password guard: blocked. " + msg + "\n")
            sys.exit(2)
    why = looks_like_secret(cmd)
    if why:
        sys.stderr.write("Claude-1Password guard: blocked — the command contains %s. A literal secret on the "
                         "command line ends up in the transcript. Save it with `op-store <title>` and use $VAR / op:// instead.\n" % why)
        sys.exit(2)


def ev_write(d):
    ti = d.get("tool_input") or {}
    text = (ti.get("content") or "") + "\n" + (ti.get("new_string") or "")
    path = ti.get("file_path", "") or ""
    why = looks_like_secret(text)
    if why:
        sys.stderr.write("Claude-1Password guard: blocked — writing %s into %s. Never write literal secrets to files. "
                         "Save it with `op-store <title>` and reference it as op://... or ${VAR} (op-env).\n" % (why, path or "a file"))
        sys.exit(2)


ASK_FOR_SECRET = re.compile(
    r"(?:paste|enter|type|send|share|provide|give me|tell me|reply with|put here|"
    r"cole|digite|envie|informe|me (?:passa|manda|d[eê])|coloque aqui|manda)"
    r"[^.\n?]{0,50}?"
    r"(?:api[ _-]?key|token|password|passphrase|senha|secret|credential|chave (?:de api|secreta)|private key)",
    re.I)
NEGATED = re.compile(r"(?:never|don'?t|do not|not|nunca|n[aã]o|jamais|instead of|rather than|without)[^.\n]{0,30}$", re.I)


def ev_stop(d):
    if d.get("stop_hook_active"):
        return
    msg = d.get("last_assistant_message", "") or ""
    for m in ASK_FOR_SECRET.finditer(msg):
        before = msg[max(0, m.start() - 40):m.start()]
        if NEGATED.search(before):
            continue
        out({"decision": "block",
             "reason": "Claude-1Password guard: you asked the user to paste a secret into the chat (\"%s\"). "
                       "Do not. Run `op-store <title>` (opens a native dialog the chat never sees), then use the "
                       "op:// reference or $VAR. Tell the user the dialog is open." % m.group(0)[:60]})
        return


def main():
    if os.environ.get("CLAUDE_1PASSWORD_GUARD", "").lower() in ("off", "0", "false"):
        return
    event = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        d = json.load(sys.stdin)
    except Exception:
        return
    {"prompt": ev_prompt, "bash": ev_bash, "write": ev_write, "stop": ev_stop}.get(event, lambda _: None)(d)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        sys.exit(0)  # fail-open
