---
description: Manage the turnstile config file — add/remove entries, or merge new baseline entries with `upgrade`.
argument-hint: <add|remove> <allow|deny|tools> <pattern or tool name> | upgrade
allowed-tools: Bash(turnstile:*)
---

The user's request is: **$ARGUMENTS**

Parse the first word as the **command**:

- `add` / `remove`: second word is the **section** (`allow`, `deny`, or `tools`); everything after is the **value**. If any are missing or invalid, ask and stop.
- `upgrade`: takes no further arguments. Merges new baseline entries (e.g. `sensitive_env_vars`, `sensitive_env_var_prefixes`) into the user's config without overwriting their additions.

Run:

```sh
turnstile <command> [<section> <value>]
```

Report what the command printed. You're done.

## Pattern guidance

For `allow` and `deny` the value is a Go RE2 regex fragment. For `tools` it is a literal tool name.

- Anchor allow patterns on the command name: `terraform\b`, `cargo\b`.
- For subcommand filtering: `cargo\s+(?:build|test|check)\b`.
- deny patterns match anywhere in a segment — prefer narrow patterns: `rm\s+-rf\s+/` over `rm\b`.

## Hard rules

Never add an entry that would allow `sudo`, `rm -rf /`, `chmod -R 777`, privileged Docker flags (`-v /`, `--privileged`), `kubectl delete`, `helm uninstall`, or reads from `.ssh` / `.aws` / `.gnupg` / `.claude`. Surface the risk instead.

Never remove a `deny` entry without the user explicitly acknowledging the risk in writing.

Do not add `Bash` to `tools` — Bash goes through the full ruleset.
