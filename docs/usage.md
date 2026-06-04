# Usage

Turnstile ships a small CLI for managing rules, previewing decisions, and inspecting tool calls. The same binary is the hook itself, so you don't need a separate daemon or service.

## Managing rules

```sh
turnstile add allow terraform            # allow a command
turnstile add deny  rm                   # block a command
turnstile add allow 'curl\s.*\|\s*sh\b'  # complex pattern, write regex directly
turnstile add tools NotebookEdit         # allow a non-Bash tool

turnstile remove allow terraform
turnstile remove tools NotebookEdit

turnstile upgrade                        # merge new baseline entries into your config
```

Bare words (letters, digits, hyphens, underscores) are automatically wrapped with `\b...\b` word boundaries before being stored, so `add allow rm` saves `\brm\b` and won't accidentally match commands that merely contain those letters. The output confirms what was stored:

```
added '\brm\b' to allow in ~/.config/turnstile/config.toml
```

When you need a precise regex (anchors, quantifiers, alternation) write it explicitly and turnstile stores it as-is. `add` validates regex syntax before writing, and it's idempotent (running it twice prints a message and exits cleanly), as is `remove`. Both preserve comments and formatting in the config file.

## Testing decisions

Use `--test` to preview a decision without running anything:

```sh
turnstile --test 'kubectl delete pod foo'
# deny: denied-pattern: kubectl: kubectl\s+delete\b

turnstile --test 'python3 scripts/run.py'
# allow

turnstile -t 'git status'
# allow
```

Exit codes are `0` for allow, `1` for ask, and `2` for deny, so you can use them directly in CI scripts.

Use `--test-tool` to check non-Bash tools (defaults to `Bash`), and `--test-json` to emit the raw hook JSON instead of pretty output.

The original JSON-on-stdin path still works for round-trip testing:

```sh
echo '{"tool_name":"Bash","tool_input":{"command":"your command here"}}' | turnstile
```

## Exit code contract

| Exit code | Decision | Meaning                                      |
|-----------|----------|----------------------------------------------|
| `0`       | `allow`  | Tool call is permitted                       |
| `1`       | `ask`    | User confirmation required                   |
| `2`       | `deny`   | Tool call is blocked                         |
| `3+`      | —        | Internal error (config parse, IO, etc.)      |
