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

Bash commands are judged by what they DO, not by the words they contain (v0.5): text inside
quoted patterns, heredocs that only write a file, and search patterns is data, not a command.
A secret file may be listed, moved, counted, sourced or read for its variable NAMES only
(grep -o/-c, sed 's/=.*//', cut -d= -f1, awk -F= '{print $1}', | wc); printing its values is blocked.

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
    ("sk- style key",        B + r"sk-(?:proj-|live_|test_|or-v1-)?[A-Za-z0-9_\-]{20,}"),
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
    # the header alone is documentation; a key needs its base64 body
    ("private key block",    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----(?:\\[rn]|\s)+[A-Za-z0-9+/=]{40,}"),
    ("JWT",                  B + r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    # user:password@ — but not user:${VAR}@ or user:<password>@
    ("password in URL",      r"[a-z][a-z0-9+.-]*://[^\s:@/]+:(?![$<{%])[^\s@/]{6,}@"),
]
KNOWN_RE = [(name, re.compile(p)) for name, p in KNOWN]
KEYWORD = r"(?:api[_\- ]?key|apikey|secret|token|password|passwd|senha|credential|client[_\- ]?secret|private[_\- ]?key|bearer)"
# keyword, then : or = or "is", then a 12+ char run with no spaces/quotes (symbols allowed: passwords have them)
KW_VALUE = re.compile(KEYWORD + r"[\"']?\s*(?:[:=]|\bis\b)\s*[\"']?([^\s\"'`]{12,})", re.I)
# values that are references, placeholders, paths, URLs or variables: never a secret
SAFE = re.compile(r"^(?:op://|https?://|[~/.$]|\$\{|<[^>]+>$|YOUR_|xxx|\.\.\.|placeholder$|changeme$|\*+$)", re.I)
CODE_ROOT = re.compile(
    r"^(?:process|os|config|cfg|conf|settings|env|environ|self|this|opts|options|args|argv|req|request|res|"
    r"ctx|context|import|Bun|Deno|window|document|globalThis|state|props|secrets|creds|credentials|auth|"
    r"session|params|data|body|payload|headers|client|app|start)\??\.[A-Za-z_$]")


def code_like(val: str) -> bool:
    """True when the 'value' after token=/password: is source code, not a secret."""
    v = val.rstrip(",;)]}")
    return bool(
        re.match(r"[A-Za-z_$][\w$]*(?:\??\.[A-Za-z_$][\w$]*){2,}", v)        # a.b.c  (process.env.X)
        or CODE_ROOT.match(v)                                                # config.x, start.y
        or re.fullmatch(r"[a-z_$][\w$]*\.[a-z]+[A-Z][A-Za-z]{3,}", v)       # obj.camelCase
        or re.match(r"[A-Za-z_$][\w$.]*\(", v)                               # getToken(...)
        or re.search(r"\[\^|\)\|\||\|\|\[|=>|\\[sSdDwW]|\(\?[:=!]|^\(", v)  # regex / JS expression
        or re.fullmatch(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+", v)                # ENV_VAR_NAME placeholder
    )


def looks_like_secret(text: str) -> str:
    """Return a short reason if text contains something that looks like a real secret, else ''."""
    if not text:
        return ""
    for name, rx in KNOWN_RE:
        if rx.search(text):
            return name
    for m in KW_VALUE.finditer(text):
        val = m.group(1)
        if SAFE.match(val) or code_like(val):
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
    r"id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?|[^\\/.][^\\/]*\.(?:pem|p12|pfx|key|keystore|jks)|"
    r"hosts\.yml|secrets?\.ya?ml|secrets?\.json"
    r")$", re.I)
PATH_OK = re.compile(
    r"\.env\.(?:tpl|example|sample|template|dist)(?:[.\-_][\w.-]*)?$|\.pub$|"
    r"(?:^|[\\/])(?:cacert|ca-bundle|ca-certificates|cert|chain|fullchain|cert-chain|ca)\.pem$", re.I)


def secret_path(p: str) -> bool:
    p = (p or "").strip().strip("\"'")
    return bool(SECRET_PATH.search(p)) and not PATH_OK.search(p)


def paths_in_word(w: str):
    # a word that looks like a path or a dotfile name; git show HEAD:.env, scp host:.env, VAR=.env
    for t in re.split(r"[\s:]", w):
        t = t.strip()
        if not t or t.startswith("-"):
            continue
        if "=" in t and not t.startswith("="):
            t = t.split("=", 1)[1]
        if "/" in t or t.startswith(".") or t.startswith("~"):
            yield t


def paths_in_command(cmd: str):
    for tok in re.findall(r"[^\s\"'`;&|<>()]+", cmd):
        yield from paths_in_word(tok)


# --- shell view: what a command DOES ------------------------------------------------------------
# Quoted strings become placeholders (__Q0__) unless the shell runs them (bash -c, ssh host, eval).
# Double quotes keep their $VAR, ${...}, $(...) and `...` because the shell expands those.
# Heredoc bodies fed to a shell are code; fed to python/node they are scripts; fed to cat/tee they are data.
HEREDOC = re.compile(r"(?<!<)<<-?\s*(['\"]?)([A-Za-z_]\w*)\1")
SHELLS = r"(?:bash|sh|zsh|dash|ksh)"
INTERPS = r"(?:python[\d.]*|node|deno|bun|ruby|perl|php|tsx|ts-node|osascript)"
EXEC_BEFORE = re.compile(
    r"(?:\b" + SHELLS + r"\b[^'\"\n;|&]*\s-[a-zA-Z]*c|\beval|\bssh\b[^'\"\n;|&]*|\bsu\b[^'\"\n;|&]*\s-c|\bwatch\b[^'\"\n;|&]*)\s*$")
SCRIPT_BEFORE = re.compile(r"\b" + INTERPS + r"\b[^'\"\n;|&]*\s-[ce]\s*$")
SEP = re.compile(r"&&|\|\||\$\(|[;\n&(){}`]")


def match_paren(s: str, k: int) -> int:
    """Index of the ')' that closes the '(' at s[k] (quotes inside are skipped)."""
    depth, j, n = 0, k, len(s)
    while j < n:
        c = s[j]
        if c == "\\":
            j += 2
            continue
        if c == "'":
            e = s.find("'", j + 1)
            j = n if e < 0 else e + 1
            continue
        if c == '"':
            j += 1
            while j < n and s[j] != '"':
                j += 2 if s[j] == "\\" else 1
            j += 1
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return j
        j += 1
    return n


class View:
    def __init__(self, cmd: str):
        self.q = []            # quoted strings, by placeholder index
        self.scripts = []      # python/node code (heredocs and -c/-e strings)
        main, docs = self._heredocs(cmd)
        parts = [self.render(main)]
        for owner, body in docs:
            seg = re.split(r"&&|\|\||[;|]", owner.split("<<")[0])[-1]
            piped = re.search(r"\|\s*(?:sudo\s+)?(?:" + SHELLS + r"|ssh)\b", owner)
            if piped or re.search(r"\b" + SHELLS + r"\b|\bssh\b", seg):
                parts.append(self.render(body))
            elif re.search(r"\b" + INTERPS + r"\b", seg):
                self.scripts.append(body)
            # else: data written by cat/tee/etc. — not a command
        self.text = "\n".join(parts)

    @staticmethod
    def _heredocs(cmd):
        lines = cmd.split("\n")
        main, docs, i = [], [], 0
        while i < len(lines):
            line = lines[i]
            main.append(line)
            i += 1
            for m in HEREDOC.finditer(line):
                delim, strip = m.group(2), line[m.start():m.start() + 3] == "<<-"
                body = []
                while i < len(lines):
                    ln = lines[i]
                    i += 1
                    if (ln.lstrip("\t") if strip else ln).strip() == delim:
                        break
                    body.append(ln)
                docs.append((line[:m.start()] + " " + line[m.end():], "\n".join(body)))
        return "\n".join(main), docs

    def render(self, s: str, depth: int = 0) -> str:
        out, i, n = [], 0, len(s)
        while i < n:
            c = s[i]
            if c == "\\":
                out.append(s[i:i + 2])
                i += 2
                continue
            if c in "'\"":
                kept = []
                if c == "'":
                    j = s.find("'", i + 1)
                    j = n if j < 0 else j
                else:  # double quotes: the shell still runs $(...) and `...` and expands $VAR inside them
                    j = i + 1
                    while j < n and s[j] != '"':
                        if s[j] == "\\":
                            j += 2
                        elif s.startswith("$(", j):
                            e = match_paren(s, j + 1)
                            kept.append("$(" + self.render(s[j + 2:e], depth + 1) + ")")
                            j = e + 1
                        elif s[j] == "`":
                            e = s.find("`", j + 1)
                            e = n if e < 0 else e
                            kept.append("`" + self.render(s[j + 1:e], depth + 1) + "`")
                            j = e + 1
                        else:
                            m = re.match(r"\$\{[^}]*\}|\$[A-Za-z_]\w*", s[j:]) if s[j] == "$" else None
                            if m:
                                kept.append(m.group(0))
                                j += len(m.group(0))
                            else:
                                j += 1
                    j = min(j, n)
                inner = s[i + 1:j]
                i = j + 1
                before = "".join(out[-40:])
                if depth < 4 and EXEC_BEFORE.search(before):
                    out.append(" ; " + self.render(inner.replace('\\"', '"') if c == '"' else inner, depth + 1) + " ; ")
                    continue
                if SCRIPT_BEFORE.search(before):
                    self.scripts.append(inner)
                k = len(self.q)
                self.q.append(inner)
                out.append(" __Q%d__ %s " % (k, " ".join(kept)))
                continue
            out.append(c)
            i += 1
        return "".join(out)

    def unq(self, w: str) -> str:
        return re.sub(r"__Q(\d+)__", lambda m: self.q[int(m.group(1))], w)

    def pipelines(self):
        """Yield (captured, [stage words...]) — captured = output goes into VAR=$(...), not the transcript."""
        chunks, pos, captured = [], 0, False
        for m in SEP.finditer(self.text):
            chunks.append((captured, self.text[pos:m.start()]))
            captured = m.group(0) == "$(" and re.search(r"\w+=(?:\s*__Q\d+__)?\s*$", self.text[:m.start()]) is not None
            pos = m.end()
        chunks.append((captured, self.text[pos:]))
        for cap, ch in chunks:
            stages = [s.split() for s in re.split(r"(?<![|>])\|(?!\|)", ch)]
            stages = [s for s in stages if s]
            if stages:
                yield cap, stages


WRAPPERS = {"sudo", "command", "exec", "nice", "nohup", "time", "builtin", "caffeinate"}


def parse_stage(words, v):
    """→ (cmd, args, reads, writes): args unquoted; reads/writes = redirect targets."""
    w = list(words)
    while w and (re.match(r"^[A-Za-z_]\w*=", w[0]) or w[0] in WRAPPERS or w[0] == "timeout"):
        if w[0] == "timeout" and len(w) > 1:
            w = w[2:]
            continue
        w = w[1:]
    if len(w) > 1 and w[0] == "env" and (re.match(r"^[A-Za-z_]\w*=", w[1]) or not w[1].startswith("-")):
        w = w[1:]
        while w and re.match(r"^[A-Za-z_]\w*=", w[0]):
            w = w[1:]
    if not w:
        return "", [], [], []
    cmd = os.path.basename(v.unq(w[0]))
    args, reads, writes, i = [], [], [], 1
    while i < len(w):
        t = w[i]
        m = re.match(r"^(\d*>>?|&>|<)(.*)$", t)
        if m and not t.startswith("<("):
            target = m.group(2) or (w[i + 1] if i + 1 < len(w) else "")
            i += 1 if m.group(2) else 2
            if m.group(1) == "<":
                reads.append(v.unq(target))
            elif not m.group(1)[0].isdigit() or m.group(1)[0] == "1":   # stdout; 2>/dev/null hides only errors
                writes.append(v.unq(target))
            continue
        args.append(v.unq(t))
        i += 1
    return cmd, args, reads, writes


def short_flags(args):
    return "".join(a[1:] for a in args if re.match(r"^-[A-Za-z]+$", a))


def first_operand(args):
    for a in args:
        if not a.startswith("-"):
            return a
    return ""


def is_mask(cmd, args):
    """Does this stage reduce KEY=value lines to names/counts only?"""
    fl = short_flags(args)
    if cmd in ("wc",):
        return True
    if cmd in ("grep", "egrep", "fgrep", "rg"):
        if set(fl) & set("clLq") or {"--count", "--quiet", "--files-with-matches"} & set(args):
            return True
        if "o" in fl:  # -o prints only the match: fine when the pattern can only match a NAME
            return bool(re.fullmatch(r"\^?[\[\]A-Za-z0-9_\-*+()|?]*=?", first_operand(args)))
        return False
    if cmd in ("sed", "gsed"):
        scripts = [args[k + 1] for k, a in enumerate(args[:-1]) if a in ("-e", "--expression")] or [first_operand(args)]
        return len(scripts) == 1 and bool(re.match(r"^s(.)=\.\*\1(?:[^\\]|\\.)*?\1[gpIi]*$", scripts[0]))
    if cmd == "cut":
        j = " ".join(args)
        return bool(re.search(r"-d\s*=", j) and re.search(r"-f\s*1(?![\d,-])", j))
    if cmd in ("awk", "gawk"):
        j = " ".join(args)
        return bool(re.search(r"-F\s*=|FS\s*=\s*\"=\"", j) and re.search(r"print\s+\$1\b", j)
                    and not re.search(r"\$(?:0|[2-9])", j))
    return False


PATTERN_FIRST = {"grep", "egrep", "fgrep", "rg", "sed", "gsed", "awk", "gawk", "jq", "yq"}
NO_FILE_ARGS = {"echo", "printf", ":", "true", "false", "cd", "for", "case", "export", "unset", "local", "read",
                "if", "then", "else", "fi", "do", "done", "while", "until", "return", "exit", "which", "type"}
META = {"ls", "stat", "file", "chmod", "chown", "chgrp", "mv", "cp", "rm", "touch", "test", "[", "[[", "wc", "du",
        "realpath", "readlink", "dirname", "basename", "mkdir", "ln", "install", "shred", "cmp", "source", ".",
        "open", "trash", "xattr", "tree"}
SECRET_NAME = re.compile(r"TOKEN|KEY|SECRET|PASS|PWD|CRED|AUTH|PRIVATE|SENHA|COOKIE|SESSION", re.I)
SAFE_FIELDS = {"username", "user", "email", "url", "website", "title", "notes", "notesplain", "tags", "label", "hostname", "server"}


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
CHECK_HINT = " To check a secret is set without printing it: op-env -- sh -c '[ -n \"$VAR\" ] && echo set'."
# run on the shell VIEW (quoted patterns and data heredocs removed)
VIEW_LEAKS = [
    (r"\bop\s+read\b(?!.*--help)", "`op read` prints the secret into the transcript. Use $VAR loaded by op-env, or op-store to save one."),
    (r"\bop\s+item\s+get\b(?![^\n;|&]*--help)", "`op item get` can print secret values (--reveal/--fields/--format json). Use $VAR from op-env." + CHECK_HINT),
    (r"\bop\s+document\s+get\b", "`op document get` prints the document. Do not."),
    (r"\bop\s+(?:run|inject)\b(?![^\n;|&]*--help)", "`op run`/`op inject` resolve every reference in a file. Only op-env may do that."),
    (r"\bop\s+signin\b.*--raw", "`op signin --raw` prints a session token."),
    (r"/proc/[^/\s]+/environ", "reading /proc/*/environ dumps the environment."),
    (r"(?:^|[;&|(`{]\s*)(?:echo|printf)\b[^|;&\n]*" + SECRET_VAR, "echoing a secret env var leaks it. Use it inside the command that needs it." + CHECK_HINT),
    (r"\$\{![\w@*]+\}", "indirect expansion over variable names dumps values."),
    (r"\bbase64\b[^|;&\n]*" + SECRET_VAR, "encoding a secret does not hide it from the transcript."),
    (r"\b(?:bash|sh|zsh)\s+-[a-zA-Z]*[xv][a-zA-Z]*\s+\S*(?:op-store|op-env|secret-dialog)|SHELLOPTS=[^ ]*xtrace", "tracing op-store/op-env prints the secret. Never trace them."),
]
# run on the raw command and on script bodies: only explicit whole-environment dumps
SCRIPT_LEAKS = re.compile(
    r"\b(?:print|pprint|pp|repr|str|dumps|write)\s*\((?:\s*dict\s*\()?\s*os\.environ\s*\)"
    r"|\bos\.environ\.(?:items|values)\s*\("
    r"|\b(?:console\.\w+|JSON\.stringify|util\.inspect|Object\.(?:entries|values))\s*\(\s*(?:process|Bun)\.env\s*[),]"
    r"|\bENV\.(?:to_h|inspect|each|to_a)\b|\bSystem\.getenv\(\)")
SCRIPT_OPEN = re.compile(r"(?:open|readFileSync|readFile|read_text|read_bytes|load_dotenv|dotenv_values|Path|fopen)\s*\(([^)]*)\)")


def ev_bash(d):
    cmd = (d.get("tool_input") or {}).get("command", "") or ""
    v = View(cmd)
    for pat, msg in VIEW_LEAKS:
        if re.search(pat, v.text, re.I | re.M):
            block(msg)
    for src in [cmd] + v.scripts:
        if SCRIPT_LEAKS.search(src):
            block("dumping the environment from a script leaks the secrets injected by op-env.")
    for src in v.scripts:
        for m in SCRIPT_OPEN.finditer(src):
            for lit in re.findall(r"['\"]([^'\"]+)['\"]", m.group(1)):
                if secret_path(lit):
                    block("'%s' is a secret file; the script would read it into the transcript. "
                          "Use op-env --list (names only), or migrate it with op-store." % lit)
    for captured, stages in v.pipelines():
        parsed = [parse_stage(s, v) for s in stages]
        for k, (c, args, reads, writes) in enumerate(parsed):
            masked = captured or any(is_mask(c2, a2) for c2, a2, _, _ in parsed[k + 1:]) \
                or any(w == "/dev/null" for w in writes)
            operands = [a for a in args if not a.startswith("-")]
            # whole-environment dumps
            if c in ("env", "printenv") and not operands and not masked:
                block("printing the whole environment leaks the secrets injected by op-env. Use `op-env --list` "
                      "(names only), or mask values: env | grep X | sed 's/=.*/=<set>/'.")
            if c == "printenv" and operands and not masked and \
                    any("$" in a or SECRET_NAME.search(a) for a in operands):
                block("printing a secret env var leaks it. Use it inside a command instead." + CHECK_HINT)
            if (c == "set" and not args) or (c == "export" and args[:1] == ["-p"]) or \
                    (c in ("declare", "typeset") and set(short_flags(args)) & set("xp") and not operands) or \
                    (c == "compgen" and "v" in short_flags(args)):
                if not masked:
                    block("dumping shell variables leaks the secrets injected by op-env.")
            # op item create/edit: values on the command line (usernames and URLs are fine)
            if c == "op" and args[:2] and args[0] == "item" and args[1] in ("create", "edit") and "--help" not in args:
                for a in args[2:]:
                    m = re.match(r"^([\w .\-]+?)(?:\[\w+\])?=", a)
                    if m and not a.startswith("-") and m.group(1).split(".")[-1].strip().lower() not in SAFE_FIELDS:
                        block("putting a value on the command line records it in the transcript. "
                              "Use `op-store <title>` (native hidden dialog).")
            # running secret-dialog directly (reading or building its source is fine)
            target = c if c.startswith("secret-dialog") else (
                os.path.basename(first_operand(args)) if c in ("bash", "sh", "zsh", "python", "python3") else "")
            if target.startswith("secret-dialog") and not re.search(r"\.(?:swift|md|txt|bak)$", target):
                block("secret-dialog prints the value it collects; only op-store may call it.")
            if c in ("declare", "typeset") and any(SECRET_NAME.search(a) for a in operands):
                block("printing a secret variable leaks it." + CHECK_HINT)
            # secret files: listing, moving, counting, sourcing, names-only reads and writes are fine
            to_screen = any(re.match(r"/dev/(?:stdout|stderr|tty|fd/)", a) for a in args + writes)
            tracing = re.search(r"\bset\s+-[a-z]*x|\bset\s+-o\s+xtrace|\b" + SHELLS + r"\s+-[a-z]*x", v.text)
            finder = c in ("find", "fd") and not {"-exec", "-execdir", "-ok", "-okdir", "-x", "--exec", "-X"} & set(args)
            if ((c in META and not to_screen and not (c in ("source", ".") and tracing)) or finder
                    or c in NO_FILE_ARGS or masked or is_mask(c, args)):
                continue
            files = list(args)
            if c in PATTERN_FIRST and not re.search(r"(?:^|\s)-[a-zA-Z]*[ef]\b", " ".join(args)):
                op = first_operand(args)
                if op in files:
                    files.remove(op)
            for f in files + reads:
                for p in paths_in_word(f):
                    if secret_path(p):
                        block("'%s' is a secret file. Printing its values puts secrets in the transcript. "
                              "Allowed: ls/mv/cp/chmod it, source it, or read NAMES only "
                              "(grep -o '^[A-Z_]*', cut -d= -f1, sed 's/=.*//'). Or migrate it with op-store." % p)
    why = looks_like_secret(cmd)
    if why:
        block("the command contains %s. A literal secret on the command line ends up in the transcript. "
              "Save it with `op-store <title>` and use $VAR / op:// instead." % why)


TAMPER_PATH = re.compile(r"(?:claude-1password|Claude-1Password|op-secrets)[\\/].*hooks[\\/]|[\\/]hooks[\\/]guard\.py$|[\\/]hooks\.json$", re.I)


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


# whole words only: "computador", "TypeSafe", "puts", "1Password", "TYPESAFE_API_KEY" and "43k token" are not requests
REQUEST = re.compile(
    r"\b(?:paste|enter|type|send|share|provide|give me|tell me|reply with|put|drop|"
    r"cole|digite|envie|informe|me (?:passa|manda|d[eê])|coloque|manda|what(?:'s| is) your)\b"
    r"[^.\n?!]{0,50}?"
    r"(?<![\w-])(?:api[ _-]?keys?|tokens?|passwords?|passphrases?|senhas?|secrets?|credentials?|chaves? (?:de api|secretas?)|private keys?)(?![\w-])",
    re.I)
NEGATED = re.compile(r"\b(?:never|don'?t|do not|not|nunca|n[aã]o|jamais|instead of|rather than|without)\b", re.I)
SAFE_PLACE = re.compile(r"\b(?:dialog|dialogue|caixa|janela|op-store|1password|native window|popup|pop-up)\b|op://", re.I)


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


def prose_only(msg: str) -> str:
    """Drop code blocks, `inline code` and quoted text: names and quotes are not requests."""
    msg = re.sub(r"```.*?(?:```|$)", " ", msg, flags=re.S)
    msg = re.sub(r"`[^`\n]*`", " ", msg)
    msg = re.sub(r"\"[^\"\n]{0,200}\"|“[^”\n]{0,200}”", " ", msg)
    return msg


def ev_stop(d):
    if d.get("stop_hook_active"):
        return
    msg = last_assistant_text(d)
    if not msg:
        return
    for sent in re.split(r"(?<=[.!?;\n])\s+", prose_only(msg)):
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
