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

Edit the config file (or [have claude do it for you](claude/skills/turnstile/SKILL.md)). Three arrays, all Go [RE2](https://github.com/google/re2/wiki/Syntax) regex fragments. Use TOML _literal strings_ (single quotes) so backslashes don't need escaping.

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

### Test a rule before committing it

```sh
echo '{"tool_name":"Bash","tool_input":{"command":"your command here"}}' | turnstile
```

### Default config

The shipped [defaults](internal/config/config.toml) (embedded in the binary) are a reasonable starting point — a broad set of development commands allowed, anything destructive or credential-adjacent denied. Trim or extend accordingly.

If you rather start from scratch, you can overwrite the default config file with the blank template below. Then customize it by hand, or have claude do it for you through the provided [skill](claude/skills/turnstile/SKILL.md).

```toml
# turnstile — PreToolUse hook ruleset.
#
# Three sections. Patterns are Go RE2 regex fragments (no lookaround, no
# backrefs). Use TOML literal strings (single quotes) so backslashes don't
# need escaping.
#
#   allow — matched against the START of each Bash command segment. The
#           allowlist; broad enough to cover routine work.
#   deny  — matched ANYWHERE in any segment. Hard block. Wins over allow.
#   tools — literal tool names (not regexes) for non-Bash tools that should
#           bypass prompting.

allow = []

deny = []

tools = []

```

### Claude Skill

You can also use the [turnstile skill](claude/skills/turnstile/SKILL.md) with Claude to have it propose and apply entries to your turnstile config file without leaving the conversation.

#### Skill Installation

Claude Code loads slash commands from `~/.claude/commands/` (user-level, available in every project) or `.claude/commands/` (project-level). The command file must be named after the slash command — `turnstile.md` for `/turnstile`.

From the repo root, run once:

```sh
mkdir -p ~/.claude/commands
cp claude/skills/turnstile/SKILL.md ~/.claude/commands/turnstile.md
```

Verify install by typing `/turnstile` in any Claude Code session — the command should appear in the autocomplete list.

#### Usage

```
/turnstile <allow|deny|tools> <pattern or tool name>
```

The command reads the current config, tests the proposed change against the live `turnstile` binary, shows you the exact diff, and waits for your confirmation before touching the file.

#### Permission self-service

Drop this into your `CLAUDE.md` (project or `~/.claude/CLAUDE.md`):

```markdown
When a Bash command is denied or blocked by the `turnstile` PreToolUse hook and the command is genuinely safe for this environment, you may propose adding it to the turnstile config file through the `/turnstile` skill.

Never add entries that would allow `sudo`, privileged Docker flags, reads from credential directories (`.ssh`, `.aws`, `.gnupg`, `.claude`), `kubectl delete`, or other destructive operations. If the denied command fits one of those categories, surface the concern instead of working around it.
```

This turns "hook blocked me" into a allow proposal the user can review.
