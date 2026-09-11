#!/usr/bin/env python3
"""guard.py — Claude Code hooks that steer secrets through 1Password (op-store / op-env).

Usage (from hooks.json):  python3 guard.py <event>     event = prompt | bash | write | read | stop
Reads the hook JSON on stdin. Fail-open: any internal error exits 0 (never blocks by accident).

What it is: a filter that catches the MISTAKES a well-behaved model makes (pasting a key, printing
an env var, reading a .env file, asking the user for a password). What it is not: a sandbox. A
prompt-injected agent can wrap, encode or split commands to get around a text filter. Real
isolation needs a credential proxy or an OS sandbox — see README "Security model".

  prompt  UserPromptSubmit          the USER pasted something that looks like a secret
                                    → block + erase the prompt (Claude never sees it), tell the user to use op-store
  bash    PreToolUse Bash           Claude's command would print a secret, read a secret file, or put a
                                    literal secret on the command line → block
  write   PreToolUse Write|Edit|MultiEdit|NotebookEdit   literal secret into a file, or tampering with this guard → block
  read    PreToolUse Read|Grep|Glob secret files by path (.env, credentials, keys) → block
  stop    Stop                      Claude just asked the user to paste a secret in chat → block, make Claude use op-store

Escape hatch for the USER only: prompt starting with "#allow-secret"; env CLAUDE_1PASSWORD_GUARD=off.
There is deliberately no per-command override the model could type.
"""
import json
import os
import re
import sys

# --- secret detector -----------------------------------------------------------------------------
B = r"(?<![A-Za-z0-9_/.-])"  # left boundary: not inside a longer word/path
KNOWN = [
    ("Anthropic key",        B + r"sk-ant-[A-Za-z0-9_\-]{20,}"),
    ("sk- style key",        B + r"sk-(?:proj-|live_|test_)?[A-Za-z0-9_\-]{20,}"),
    ("GitHub token",         B + r"gh[pousr]_[A-Za-z0-9]{30,}"),
    ("GitHub token",         B + r"github_pat_[A-Za-z0-9_]{50,}"),
    ("1Password SA token",   B + r"ops_[A-Za-z0-9]{100,}"),
    ("Slack token",          B + r"xox[abprs]-[A-Za-z0-9\-]{20,}"),
    ("AWS access key",       B + r"AKIA[0-9A-Z]{16}"),
    ("Google API key",       B + r"AIza[0-9A-Za-z_\-]{35}"),
    ("Google OAuth token",   B + r"ya29\.[A-Za-z0-9_\-]{40,}"),
    ("GitLab token",         B + r"glpat-[A-Za-z0-9_\-]{20}"),
    ("npm token",            B + r"npm_[A-Za-z0-9]{36}"),
    ("PyPI token",           B + r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{30,}"),
    ("Apify token",          B + r"apify_api_[A-Za-z0-9]{20,}"),
    ("Hugging Face token",   B + r"hf_[A-Za-z0-9]{30,}"),
    ("Doppler token",        B + r"dop_v1_[a-f0-9]{40,}"),
    ("Stripe key",           B + r"[rs]k_live_[A-Za-z0-9]{20,}"),
    ("Stripe webhook secret", B + r"whsec_[A-Za-z0-9]{20,}"),
    ("SendGrid key",         B + r"SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}"),
    ("Telegram bot token",   B + r"[0-9]{8,10}:AA[A-Za-z0-9_\-]{30,}"),
    ("private key block",    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
    ("JWT",                  B + r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    ("password in URL",      r"[a-z][a-z0-9+.-]*://[^\s:@/]+:[^\s@/]{6,}@"),
]
KNOWN_RE = [(name, re.compile(p)) for name, p in KNOWN]
KEYWORD = r"(?:api[_\- ]?key|apikey|secret|token|password|passwd|senha|credential|client[_\- ]?secret|private[_\- ]?key|bearer)"
# keyword, then : or = or "is", then a 12+ char run with no spaces/quotes (symbols allowed: passwords have them)
KW_VALUE = re.compile(KEYWORD + r"[\"']?\s*(?:[:=]|\bis\b)\s*[\"']?([^\s\"'`]{12,})", re.I)
# values that are references, placeholders, paths, URLs or variables: never a secret
SAFE = re.compile(r"^(?:op://|https?://|[~/.$]|\$\{|<[^>]+>$|YOUR_|xxx|\.\.\.|placeholder$|changeme$|\*+$)", re.I)


def looks_like_secret(text: str) -> str:
    """Return a short reason if text contains something that looks like a real secret, else ''."""
    if not text:
        return ""
    for name, rx in KNOWN_RE:
        if rx.search(text):
            return name
    for m in KW_VALUE.finditer(text):
        val = m.group(1)
        if SAFE.match(val):
            continue
        if re.fullmatch(r"[A-Za-z]+", val):  # a plain word, e.g. "password is required"
            continue
        has_digit = re.search(r"\d", val) is not None
        mixed_case = re.search(r"[A-Z]", val) is not None and re.search(r"[a-z]", val) is not None
        if has_digit or mixed_case:
            return "a value after '%s'" % re.sub(r"\s+", " ", m.group(0)[:10]).strip()
    return ""


# --- secret files by path -------------------------------------------------------------------------
SECRET_PATH = re.compile(
    r"(?:^|[\\/])(?:"
    r"\.env(?:\.[\w.-]+)?|\.envrc|\.netrc|\.npmrc|\.pgpass|\.pypirc|\.git-credentials|"
    r"credentials(?:\.json)?|\.credentials\.json|token\.json|service[-_]?account[^\\/]*\.json|"
    r"id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?|[^\\/]*\.(?:pem|p12|pfx|key|keystore|jks)|"
    r"hosts\.yml|secrets?\.ya?ml|secrets?\.json"
    r")$", re.I)
PATH_OK = re.compile(r"\.env\.(?:tpl|example|sample|template|dist)$|\.pub$|(?:^|[\\/])\.env\.tpl$", re.I)


def secret_path(p: str) -> bool:
    p = (p or "").strip().strip("\"'")
    return bool(SECRET_PATH.search(p)) and not PATH_OK.search(p)


def paths_in_command(cmd: str):
    # every token that looks like a path or a dotfile name
    for tok in re.findall(r"[^\s\"'`;&|<>()]+", cmd):
        for t in tok.split(":"):   # git show HEAD:.env, scp host:.env, VAR=.env
            t = t.strip()
            if not t or t.startswith("-"):
                continue
            if "=" in t and not t.startswith("="):
                t = t.split("=", 1)[1]
            if "/" in t or t.startswith(".") or t.startswith("~"):
                yield t


# --- events ------------------------------------------------------------------------------------
def out(obj):
    sys.stdout.write(json.dumps(obj))
    sys.stdout.flush()


def block(msg):
    sys.stderr.write("Claude-1Password guard: blocked. " + msg + "\n")
    sys.exit(2)


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


SECRET_VAR = r"\$\{?[A-Za-z_]*(?:TOKEN|KEY|SECRET|PASS|PASSWORD|PASSWD|CREDENTIAL|CRED|AUTH)[A-Za-z0-9_]*\}?"
BASH_LEAKS = [
    (r"\bop\s+read\b", "`op read` prints the secret into the transcript. Use $VAR loaded by op-env, or op-store to save one."),
    (r"\bop\s+item\s+get\b", "`op item get` can print secret values (--reveal/--fields/--format json). Use $VAR from op-env."),
    (r"\bop\s+document\s+get\b", "`op document get` prints the document. Do not."),
    (r"\bop\s+(?:run|inject)\b", "`op run`/`op inject` resolve every reference in a file. Only op-env may do that."),
    (r"\bop\s+signin\b.*--raw", "`op signin --raw` prints a session token."),
    (r"\bop\s+item\s+(?:create|edit)\b", "putting a value on the command line records it in the transcript. Use `op-store <title>` (native hidden dialog)."),
    (r"\bsecret-dialog\b", "secret-dialog prints the value it collects; only op-store may call it."),
    (r"(?:^|[;&|(`{]\s*)(?:printenv|env)(?:\s+-0)?\s*(?:$|[;&|>)}])", "printing the whole environment leaks the secrets injected by op-env. Use `op-env --list` (names only)."),
    (r"(?:^|[;&|(`{]\s*)printenv\s+", "printing an env var leaks it. Use it inside a command instead."),
    (r"(?:^|[;&|(`{]\s*)(?:set|export\s+-p|declare\s+-[xp]|typeset\s+-[xp]|compgen\s+-v)\s*(?:$|[;&|>)}])", "dumping shell variables leaks the secrets injected by op-env."),
    (r"/proc/[^/\s]+/environ", "reading /proc/*/environ dumps the environment."),
    (r"\bos\.environ\b|\bprocess\.env\b|\bENV\.(?:to_h|inspect|each)\b|\bSystem\.getenv\(\)", "dumping the environment from a script leaks the secrets injected by op-env."),
    (r"(?:^|[;&|(`{]\s*)(?:echo|printf)\b[^|;&]*" + SECRET_VAR, "echoing a secret env var leaks it. Use it inside the command that needs it."),
    (r"\$\{!\w+\}", "indirect expansion over variable names dumps values."),
    (r"\bbase64\b[^|;&]*" + SECRET_VAR, "encoding a secret does not hide it from the transcript."),
    (r"\b(?:bash|sh|zsh)\s+-[a-zA-Z]*[xv][a-zA-Z]*\s+\S*(?:op-store|op-env|secret-dialog)|SHELLOPTS=[^ ]*xtrace", "tracing op-store/op-env prints the secret. Never trace them."),
]


def ev_bash(d):
    cmd = (d.get("tool_input") or {}).get("command", "") or ""
    for pat, msg in BASH_LEAKS:
        if re.search(pat, cmd, re.I | re.M):
            block(msg)
    for p in paths_in_command(cmd):
        if secret_path(p):
            block("'%s' is a secret file. Reading or writing it puts secrets in the transcript. "
                  "Use op-env --list (names only), or migrate it with op-store." % p)
    why = looks_like_secret(cmd)
    if why:
        block("the command contains %s. A literal secret on the command line ends up in the transcript. "
              "Save it with `op-store <title>` and use $VAR / op:// instead." % why)


TAMPER_PATH = re.compile(r"(?:claude-1password|Claude-1Password)[\\/].*hooks[\\/]|[\\/]hooks[\\/]guard\.py$|[\\/]hooks\.json$", re.I)


def ev_write(d):
    ti = d.get("tool_input") or {}
    path = ti.get("file_path") or ti.get("notebook_path") or ""
    parts = [ti.get("content") or "", ti.get("new_string") or "", ti.get("new_source") or ""]
    for e in ti.get("edits") or []:
        parts.append((e or {}).get("new_string") or "")
    text = "\n".join(parts)
    if TAMPER_PATH.search(path):
        block("editing the Claude-1Password guard from inside a session is not allowed. Ask the user to change it.")
    if "CLAUDE_1PASSWORD_GUARD" in text and re.search(r"settings(?:\.local)?\.json$|\.claude[\\/]", path):
        block("switching the guard off from inside a session is not allowed. Only the user may set CLAUDE_1PASSWORD_GUARD.")
    if secret_path(path):
        block("'%s' is a secret file. Do not write secrets to files; use op-store and reference them as op:// or ${VAR}." % path)
    why = looks_like_secret(text)
    if why:
        block("writing %s into %s. Never write literal secrets to files. "
              "Save it with `op-store <title>` and reference it as op://... or ${VAR} (op-env)." % (why, path or "a file"))


def ev_read(d):
    ti = d.get("tool_input") or {}
    for key in ("file_path", "path", "notebook_path"):
        p = ti.get(key) or ""
        if p and secret_path(p):
            block("'%s' is a secret file. Its contents would land in the transcript. "
                  "Use op-env --list for the variable names, or migrate it with op-store." % p)
    pat = ti.get("pattern") or ""
    if d.get("tool_name") == "Grep" and looks_like_secret(pat):
        block("grepping for a secret value puts it in the transcript.")


REQUEST = re.compile(
    r"(?:paste|enter|type|send|share|provide|give me|tell me|reply with|put|drop|"
    r"cole|digite|envie|informe|me (?:passa|manda|d[eê])|coloque|manda|what(?:'s| is) your|your)"
    r"[^.\n?!]{0,50}?"
    r"(?:api[ _-]?key|token|password|passphrase|senha|secret|credential|chave (?:de api|secreta)|private key)",
    re.I)
NEGATED = re.compile(r"\b(?:never|don'?t|do not|not|nunca|n[aã]o|jamais|instead of|rather than|without)\b", re.I)
SAFE_PLACE = re.compile(r"\b(?:dialog|dialogue|caixa|janela|op-store|1password app|native window|popup|pop-up)\b", re.I)


def last_assistant_text(d):
    msg = d.get("last_assistant_message")
    if isinstance(msg, str):
        return msg
    # fallback: the transcript (may lag; best effort)
    tp = d.get("transcript_path") or ""
    try:
        text = ""
        with open(tp, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                try:
                    j = json.loads(line)
                except Exception:
                    continue
                if j.get("type") == "assistant":
                    c = (j.get("message") or {}).get("content") or []
                    t = "".join(x.get("text", "") for x in c if isinstance(x, dict) and x.get("type") == "text")
                    if t:
                        text = t
        return text
    except Exception:
        return ""


def ev_stop(d):
    if d.get("stop_hook_active"):
        return
    msg = last_assistant_text(d)
    if not msg:
        return
    for sent in re.split(r"(?<=[.!?;\n])\s+", msg):
        m = REQUEST.search(sent)
        if not m:
            continue
        if NEGATED.search(sent) or SAFE_PLACE.search(sent):
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
    {"prompt": ev_prompt, "bash": ev_bash, "write": ev_write, "read": ev_read, "stop": ev_stop}.get(event, lambda _: None)(d)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        sys.exit(0)  # fail-open
