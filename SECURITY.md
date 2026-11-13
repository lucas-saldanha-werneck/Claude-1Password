# Security Policy

## Reporting a vulnerability

Please report it privately: open the repository's **Security** tab and choose **Report a vulnerability**
(https://github.com/lucas-saldanha-werneck/op-secrets/security/advisories/new). Please do not open a public issue for a
security problem.

## Supported versions

Only the latest release (0.6.6) is supported. Fixes go into a new release.

## What op-secrets accesses

- Runs `op` (the 1Password CLI) to save and load secrets. With the desktop-app integration `op` can read every vault of your account while the app is unlocked, so a `Claude` vault is tidy, not a boundary (see "Security model, honestly" in the README).
- The hooks read your prompts and Claude's tool calls locally to catch pasted secrets and commands that would print them. They are a filter, not a sandbox.
- Secret values never go on a command line or into the transcript. `op-env` injects them into the environment of the command it launches; `op-env` logs only `op`'s error output to `~/Library/Logs/op-env.log`. A service-account token can be kept in the macOS Keychain item `op-env-sa`.
- No network requests of its own beyond what `op` does.
