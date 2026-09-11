#!/bin/bash
# tests/run.sh — feed fake hook JSON to hooks/guard.py and check block / allow.
# All "secrets" below are made-up strings in known formats, never real.
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
G="$HERE/hooks/guard.py"
pass=0; fail=0

# expect <block|allow> <event> <json>
expect() {
  local want="$1" ev="$2" json="$3" got
  local outp errp rc
  outp=$(printf '%s' "$json" | python3 "$G" "$ev" 2>/tmp/guard-test.err); rc=$?
  errp=$(cat /tmp/guard-test.err)
  if [ $rc -eq 2 ] || printf '%s' "$outp" | grep -q '"decision": *"block"'; then got=block; else got=allow; fi
  if [ "$got" = "$want" ]; then pass=$((pass+1)); printf '  ok    %-5s %-6s %s\n' "$want" "$ev" "${json:0:70}"
  else fail=$((fail+1)); printf '  FAIL  want=%s got=%s %s %s\n        out=%s err=%s\n' "$want" "$got" "$ev" "${json:0:90}" "${outp:0:100}" "${errp:0:100}"; fi
}
j() { python3 -c 'import json,sys; print(json.dumps(json.loads(sys.argv[1])))' "$1"; }

echo "prompt (UserPromptSubmit)"
expect block prompt "$(j '{"prompt":"here is my key sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"}')"
expect block prompt "$(j '{"prompt":"token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef123456"}')"
expect block prompt "$(j '{"prompt":"minha senha: Xk9$mQ2pLw7vR4tZ"}')"
expect block prompt "$(j '{"prompt":"api_key=AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"}')"
expect block prompt "$(j '{"prompt":"AKIAIOSFODNN7EXAMPLE is the aws id"}')"
expect allow prompt "$(j '{"prompt":"store my apify key in 1password"}')"
expect allow prompt "$(j '{"prompt":"the password field is required by the form"}')"
expect allow prompt "$(j '{"prompt":"use op://Claude/Apify/credential in the template"}')"
expect allow prompt "$(j '{"prompt":"set API_KEY=${APIFY_TOKEN} in .mcp.json"}')"
expect allow prompt "$(j '{"prompt":"#allow-secret sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"}')"
expect allow prompt "$(j '{"prompt":"what is a jwt token?"}')"

echo "bash (PreToolUse)"
expect block bash "$(j '{"tool_name":"Bash","tool_input":{"command":"op read \"op://Claude/Apify/credential\""}}')"
expect block bash "$(j '{"tool_name":"Bash","tool_input":{"command":"op item get Apify --vault Claude --reveal"}}')"
expect block bash "$(j '{"tool_name":"Bash","tool_input":{"command":"cd /x && printenv"}}')"
expect block bash "$(j '{"tool_name":"Bash","tool_input":{"command":"env | grep TOKEN"}}')"
expect block bash "$(j '{"tool_name":"Bash","tool_input":{"command":"echo $APIFY_TOKEN"}}')"
expect block bash "$(j '{"tool_name":"Bash","tool_input":{"command":"cat ~/.claude/.env.apify"}}')"
expect block bash "$(j '{"tool_name":"Bash","tool_input":{"command":"bash -x ~/.local/bin/op-store Apify"}}')"
expect block bash "$(j '{"tool_name":"Bash","tool_input":{"command":"op item create --title Apify credential=abc"}}')"
expect block bash "$(j '{"tool_name":"Bash","tool_input":{"command":"export GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef123456"}}')"
expect allow bash "$(j '{"tool_name":"Bash","tool_input":{"command":"op-store Apify"}}')"
expect allow bash "$(j '{"tool_name":"Bash","tool_input":{"command":"op-env --check && op-env --list"}}')"
expect allow bash "$(j '{"tool_name":"Bash","tool_input":{"command":"op vault list && op item list --vault Claude"}}')"
expect allow bash "$(j '{"tool_name":"Bash","tool_input":{"command":"curl -s -o out.json -H \"Authorization: Bearer $APIFY_TOKEN\" https://api.apify.com/v2/acts"}}')"
expect allow bash "$(j '{"tool_name":"Bash","tool_input":{"command":"echo APIFY_TOKEN=op://Claude/Apify/credential >> ~/.claude/.env.tpl"}}')"
expect allow bash "$(j '{"tool_name":"Bash","tool_input":{"command":"ls -la ~/.claude/ && git status"}}')"
expect allow bash "$(j '{"tool_name":"Bash","tool_input":{"command":"ALLOW_SECRET=1 op read op://Claude/x/credential"}}')"
expect allow bash "$(j '{"tool_name":"Bash","tool_input":{"command":"grep -rn \"password\" src/ --include=*.py"}}')"

echo "write (PreToolUse Write|Edit)"
expect block write "$(j '{"tool_name":"Write","tool_input":{"file_path":".env","content":"APIFY_TOKEN=apify_api_AbCdEfGhIjKlMnOpQrStUvWx12345\n"}}')"
expect block write "$(j '{"tool_name":"Edit","tool_input":{"file_path":"settings.json","new_string":"\"ANTHROPIC_API_KEY\": \"sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789\""}}')"
expect allow write "$(j '{"tool_name":"Write","tool_input":{"file_path":".env.tpl","content":"APIFY_TOKEN=op://Claude/Apify/credential\n"}}')"
expect allow write "$(j '{"tool_name":"Edit","tool_input":{"file_path":".mcp.json","new_string":"\"APIFY_TOKEN\": \"${APIFY_TOKEN}\""}}')"
expect allow write "$(j '{"tool_name":"Write","tool_input":{"file_path":"README.md","content":"Set your API key in 1Password, never in this file.\n"}}')"

echo "stop (Stop)"
expect block stop "$(j '{"stop_hook_active":false,"last_assistant_message":"Sure. Please paste your Apify API key here and I will save it."}')"
expect block stop "$(j '{"stop_hook_active":false,"last_assistant_message":"Me passa a senha do UniFi que eu configuro."}')"
expect block stop "$(j '{"stop_hook_active":false,"last_assistant_message":"Cole o token aqui."}')"
expect allow stop "$(j '{"stop_hook_active":false,"last_assistant_message":"Never paste your API key here. I opened a dialog; paste it there."}')"
expect allow stop "$(j '{"stop_hook_active":false,"last_assistant_message":"Do not send the password in chat. Use op-store."}')"
expect allow stop "$(j '{"stop_hook_active":false,"last_assistant_message":"The dialog is open. Paste the value in the dialog, then click OK."}')"
expect allow stop "$(j '{"stop_hook_active":true,"last_assistant_message":"Please paste your API key here."}')"
expect allow stop "$(j '{"stop_hook_active":false,"last_assistant_message":"Done. The token is stored as op://Claude/Apify/credential."}')"

echo
echo "passed: $pass  failed: $fail"
[ $fail -eq 0 ]
