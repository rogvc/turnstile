# Turnstile

A fast, configurable PreToolUse hook for [Claude Code](https://docs.claude.com/en/docs/claude-code). Every tool call is vetted against a TOML ruleset and returned as `allow`, `ask`, or `deny` before Claude sees it.

Written in Go. In-process decision logic runs in under 1ms; total wall time per invocation is ~15–25ms warm (Go startup overhead), more if cold.

## Install

```sh
go install github.com/rogvc/turnstile@latest
```

That's it.

Note that the first time you run turnstile, if no config file exists at the resolved path, the embedded default is written there and used.

## Wire it into Claude Code

Merge this into `~/.claude/settings.json` (assumes `$(go env GOPATH)/bin` is on your `PATH`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "hooks": [{ "type": "command", "command": "turnstile", "timeout": 1 }]
      }
    ]
  }
}
```

> If `$GOPATH/bin` isn't on your `PATH`, use `$(go env GOPATH)/bin/turnstile` as the command.

## How it works

Input on stdin: `{"tool_name": "...", "tool_input": {...}}`.
Output on stdout: `{"hookSpecificOutput": {"permissionDecision": "allow|ask|deny", ...}}`.

For `Bash` commands:

1. Backtick subshells → `ask`.
2. `$(...)` subshells are recursively validated against the same rules.
3. Output redirection (`>`, `>>`) → `ask`, except `>/dev/null`, `2>&1`, `>&2`.
4. Command is split on `|`, `||`, `&&`, `;`, newlines (quote-aware).
5. Any segment matches `deny` → `deny`.
6. All segments match `allow` → `allow`.
7. Otherwise → `ask` with the first unrecognised token in the reason.

For non-Bash tools: `allow` if the tool name is in `tools`, otherwise `ask`.

## Configuring your own permissions

Three arrays, all Go [RE2](https://github.com/google/re2/wiki/Syntax) regex fragments. Use TOML _literal strings_ (single quotes) so backslashes don't need escaping.

```toml
allow = ['git\b', 'ls\b', 'kubectl\b', '\w+=']
deny  = ['sudo\b', 'rm\s+-rf\s+/', 'kubectl\s+delete\b']
tools = ["Read", "Grep", "Write", "Edit"]
```

- `allow` is matched against the start of each command segment. Allowlist for routine work.
- `deny` is matched anywhere in any segment. Explicit block list. Wins over `allow`.
- `tools` contains literal tool names (not regexes).

Patterns are OR'd together and compiled once at startup. Adding rules has no measurable runtime cost.

The config file is resolved first through `$TURNSTILE_CONFIG`, then `<UserConfigDir>/turnstile/config.toml`.

If the config contains an invalid regex, the hook emits `ask` with a clear reason rather than failing silently.

### Managing rules from the CLI

```sh
turnstile add allow 'terraform\b'        # allow a new command
turnstile add deny  'curl\s.*\|\s*sh\b'  # hard-block a pattern
turnstile add tools NotebookEdit         # allow a non-Bash tool

turnstile remove allow 'terraform\b'
turnstile remove tools NotebookEdit
```

`add` validates regex syntax for `allow`/`deny` before writing and is idempotent — running it twice prints a message and exits cleanly. `remove` is likewise idempotent. Both preserve comments and existing formatting in the config file.

### Test a rule before committing it

Use the `--test` flag to preview a decision without constructing JSON on the command line:

```sh
turnstile --test 'kubectl delete pod foo'
# deny: Blocked: 'kubectl' matched pattern kubectl\s+delete\b

turnstile --test 'python3 scripts/run.py'
# allow

turnstile -t 'git status'
# allow
```

Exit codes: `0` for allow, `1` for ask, `2` for deny — usable in CI scripts.

Use `--test-tool` to check non-Bash tools (default: `Bash`), and `--test-json` to emit the raw hook JSON instead of pretty output.

The original JSON-on-stdin path still works for round-trip testing:

```sh
echo '{"tool_name":"Bash","tool_input":{"command":"your command here"}}' | turnstile
```

### Default config

The shipped [defaults](internal/config/config.toml) (embedded in the binary) are a reasonable starting point — a broad set of development commands allowed, anything destructive or credential-adjacent denied. Trim or extend accordingly.

If you rather start from scratch, overwrite the config file with this blank template:

```toml
allow = []

deny = []

tools = []
```

### Claude Skill

Install the skill to let Claude manage your rules directly from conversation.

#### Installation

Claude Code loads skills from `~/.claude/skills/` (user-level, available in every project) or `.claude/skills/` (project-level).

From the repo root, run once:

```sh
mkdir -p ~/.claude/skills/turnstile
cp claude/skills/turnstile/SKILL.md ~/.claude/skills/turnstile/SKILL.md
```

Verify by typing `/turnstile` in any Claude Code session.

#### Usage

```
/turnstile add allow 'terraform\b'
/turnstile remove tools NotebookEdit
```

Claude runs `turnstile add` or `turnstile remove` and reports the result. No config reading, no diff preview, no confirmation step.

#### Permission self-service

Drop this into your `CLAUDE.md` (project or `~/.claude/CLAUDE.md`):

```markdown
When a Bash command or tool is blocked by the `turnstile` PreToolUse hook and the request is genuinely safe for this environment, run `turnstile add <section> <value>` to allow it without asking me first.

Never add entries that would allow `sudo`, privileged Docker flags, reads from credential directories (`.ssh`, `.aws`, `.gnupg`, `.claude`), `kubectl delete`, or other destructive operations. Surface the concern instead.
```

This turns "hook blocked me" into an immediate fix rather than a multi-step proposal.
