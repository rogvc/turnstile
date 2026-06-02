# Turnstile

*A fast, simple, deterministic Claude Code auto-allow mode, for the masses.*

[![CI](https://img.shields.io/github/actions/workflow/status/rogvc/turnstile/ci.yml?branch=main&label=CI&logo=github)](https://github.com/rogvc/turnstile/actions)
[![Go Reference](https://pkg.go.dev/badge/github.com/rogvc/turnstile.svg)](https://pkg.go.dev/github.com/rogvc/turnstile)
[![Go Report Card](https://goreportcard.com/badge/github.com/rogvc/turnstile)](https://goreportcard.com/report/github.com/rogvc/turnstile)
[![Release](https://img.shields.io/github/v/release/rogvc/turnstile)](https://github.com/rogvc/turnstile/releases)
[![License](https://img.shields.io/github/license/rogvc/turnstile)](LICENSE)

Turnstile lets Claude Code run the safe commands you'd never bother to confirm and stops the dangerous ones before they reach the model. It's a [PreToolUse hook](https://code.claude.com/docs/en/hooks) that returns `allow`, `ask`, or `deny` from a TOML ruleset in a couple of milliseconds.

## Why turnstile?

Claude Code's built-in [`permissions`](https://code.claude.com/docs/en/settings#permissions) block uses exact string matching and operates after the tool call reaches the harness. Turnstile operates at the [PreToolUse hook](https://code.claude.com/docs/en/hooks) stage with [RE2 regular expressions](https://github.com/google/re2/wiki/Syntax), gives deny precedence over allow, supports scoped `cd` roots to prevent directory traversal, and parses Bash commands segment-by-segment to validate pipelines, subshells, and redirections independently. This makes it straightforward to express policies like "allow all git commands except those that modify remote state" or "block kubectl delete anywhere in a pipeline."

## Quickstart

### Install

```sh
go install github.com/rogvc/turnstile@latest
```

### Wire it up

```sh
turnstile install
```

Or manually merge this into `~/.claude/settings.json` (assumes `turnstile` is on your `PATH`):

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

### Verify

```sh
turnstile --test 'git status'
# Expected: allow

turnstile --test 'sudo rm -rf /'
# Expected: deny
```

## Usage

Turnstile provides a CLI for managing rules, testing decisions, and examining tool calls.

### Managing rules

```sh
turnstile add allow terraform            # allow a command
turnstile add deny  rm                   # block a command
turnstile add allow 'curl\s.*\|\s*sh\b'  # complex pattern — write regex directly
turnstile add tools NotebookEdit         # allow a non-Bash tool

turnstile remove allow terraform
turnstile remove tools NotebookEdit

turnstile upgrade                        # merge new baseline entries into your config
```

Bare words (letters, digits, hyphens, underscores) are automatically wrapped with `\b...\b` word boundaries before being stored, so `add allow rm` saves `\brm\b` and won't accidentally match commands that merely contain those letters. The output confirms what was stored:

```
added '\brm\b' to allow in ~/.config/turnstile/config.toml
```

When you need a precise regex — anchors, quantifiers, alternation — write it explicitly and turnstile stores it as-is. `add` validates regex syntax before writing and is idempotent — running it twice prints a message and exits cleanly. `remove` is likewise idempotent. Both preserve comments and formatting in the config file.

### Testing decisions

Use `--test` to preview a decision:

```sh
turnstile --test 'kubectl delete pod foo'
# deny: denied-pattern: kubectl: kubectl\s+delete\b

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

### Exit code contract

| Exit code | Decision | Meaning                                      |
|-----------|----------|----------------------------------------------|
| `0`       | `allow`  | Tool call is permitted                       |
| `1`       | `ask`    | User confirmation required                   |
| `2`       | `deny`   | Tool call is blocked                         |
| `3+`      | —        | Internal error (config parse, IO, etc.)      |

## Configuration

Turnstile resolves its config path in this order:

1. `$TURNSTILE_CONFIG` — explicit path to a config file you manage
2. `$XDG_CONFIG_HOME/turnstile/config.toml` — if `XDG_CONFIG_HOME` is set
3. [`os.UserConfigDir`](https://pkg.go.dev/os#UserConfigDir)`/turnstile/config.toml` — platform default (`~/Library/Application Support` on macOS, `%AppData%` on Windows, `~/.config` on Linux)

The first time turnstile runs and no config file exists at the resolved path, the embedded [default ruleset](internal/config/config.toml) is written there automatically. The defaults allow a broad set of development commands and block anything destructive or credential-adjacent.

After loading, turnstile writes a compiled cache file (e.g., `config.cache.gob`) alongside the source. On subsequent invocations, if the cache is newer than the source, the cache is loaded directly, avoiding TOML parsing and regex recompilation. Typical speedup: 30-40%. If the source file is modified, the cache is automatically invalidated.

### Core arrays

Three arrays, all [RE2 regex](https://github.com/google/re2/wiki/Syntax) fragments. Use TOML literal strings (single quotes) so backslashes don't need escaping.

```toml
allow = ['\bgit\b', '\bls\b', '\bkubectl\b', '\w+=']
deny  = ['\bsudo\b', 'rm\s+-rf\s+/', 'kubectl\s+delete\b']
tools = ["Read", "Grep", "Write", "Edit"]
```

- `allow` is matched against the start of each command segment. Allowlist for routine work.
- `deny` is matched anywhere in any segment. Explicit block list. Wins over `allow`.
- `tools` contains literal tool names (not regexes).

When you use `turnstile add` to manage entries, bare command names are automatically stored with `\b` word boundaries — so `turnstile add allow git` writes `\bgit\b`, not `git`. Writing `git` without boundaries would match any command containing those letters as a substring. If you edit the file directly, use `\b` explicitly.

Patterns are OR'd together and compiled once at startup using Go's [`regexp.Compile`](https://pkg.go.dev/regexp#Compile). Adding rules has no measurable runtime cost.

### Recipes

#### Allow Terraform, block everything else by default

```toml
allow = ['terraform\b', 'git\b', 'ls\b', 'cat\b']
deny  = []
tools = ["Read", "Grep"]
```

#### Block kubectl delete, allow the rest

```toml
allow = ['kubectl\b', 'git\b']
deny  = ['kubectl\s+delete\b']
tools = ["Read", "Edit"]
```

#### Scoped cd roots + curated allowlist

```toml
allow = ['git\b', 'npm\b', 'go\b', 'make\b', 'cat\b', 'ls\b', 'find\b']
deny  = ['rm\s+-rf\b', 'sudo\b', '\bssh\b', 'curl.*\|.*sh']
tools = ["Read", "Edit", "Grep", "Write"]
project_roots = ["/home/me/work", "/home/me/projects"]
```

When `project_roots` is set, `cd` commands with absolute paths (`/...`), home-relative paths (`~...`), or parent-relative traversal (`..`) are checked against the roots. If the target does not start with a configured root, the hook returns `ask` with reason `cd-outside-roots: <path>`. Relative paths without `..` are always allowed.

Examples with `project_roots = ["/home/me/work"]`:

- `cd /home/me/work/repo && git status` — allow (inside root)
- `cd /etc && cat shadow` — ask (outside root)
- `cd && pwd` — allow (no path argument)
- `cd ../../other && ls` — ask (relative `..` escape)
- `cd subdir && ls` — allow (relative, no traversal)

### Environment variable contract

When `$TURNSTILE_CONFIG` is set, the path is canonicalized with [`filepath.Clean`](https://pkg.go.dev/path/filepath#Clean) and symlinks are resolved with [`filepath.EvalSymlinks`](https://pkg.go.dev/path/filepath#EvalSymlinks). The file must already exist and be owned by the current user (UID match) to prevent privilege escalation attacks where a malicious environment points turnstile at a permissive config controlled by another user. If any check fails, turnstile returns an error rather than proceeding.

For the default path, turnstile seeds an empty config with safe defaults if the file doesn't exist. If the config contains an invalid regex, the hook emits `ask` with a clear reason rather than failing silently.

### Additional configuration keys

Beyond the core arrays, turnstile supports several optional keys for advanced scenarios.

#### `project_roots`

Array of absolute directory paths. When set, restricts `cd` commands to those paths and their subdirectories. See the recipe above for examples.

#### `tools_default_to_defer`

Boolean, defaults to `false`. When `true`, unknown non-Bash tools return `defer` instead of `ask`, delegating the decision to Claude Code's built-in `settings.json` permission rules. This is useful if you want turnstile to act purely as a Bash command filter and let the harness handle MCP tool prompts.

```toml
tools_default_to_defer = true
```

#### `strip_wrappers`

Array of command prefixes to remove before validation. Useful for wrapper utilities like `time`, `nice`, or `nohup` that don't affect command semantics but would otherwise trigger an `ask` prompt.

```toml
strip_wrappers = ["time", "nice", "nohup"]
```

With this setting, `time git status` is validated as `git status`.

#### `safe_path_exemptions`

Array of tables defining path exemptions for deny patterns. Each exemption has three fields:

- `scope`: descriptive label for the exemption
- `flag_pattern`: RE2 regex with one capture group extracting the path from a flag argument
- `paths`: array of allowed path prefixes

This is primarily used to permit Docker volume mounts for `/tmp` or `/var/tmp` while still blocking other host mounts. The `flag_pattern` must capture the path in the first capture group. Turnstile verifies that captured paths match an allowed prefix and are not directory traversals, then rewrites violating arguments to `__UNSAFE_PATH__` which triggers the deny pattern.

```toml
[[safe_path_exemptions]]
scope = "docker-tmp-mounts"
flag_pattern = '(?:-v|--volume)(?:=|\s+)([^:]+):'
paths = ["/tmp", "/var/tmp"]
```

With this exemption, `docker run -v /tmp/data:/data ubuntu` is allowed, but `docker run -v /etc:/data ubuntu` is denied.

#### Subshell-assigned environment variables

A common pattern in scripts is capturing a value into a variable and passing it to a subsequent command:

```bash
VER=$(git describe --tags --abbrev=0)
ARTIFACT=$(find dist -name '*.tar.gz' | head -1)
echo "Releasing $VER from $ARTIFACT"
```

When each `$(…)` body passes subshell validation, the standalone assignment segment would otherwise require a matching allow-list entry. Turnstile auto-allows these segments instead: the subshell body has already been fully vetted, deny patterns have already run, and the assignment itself executes no command.

The auto-allow only applies to bare `VAR=$(…)` segments. The `export VAR=$(…)` form is treated as a regular `export` invocation and still needs an allow-list entry — add `export\b` (or a more specific pattern) if you want it through.

A curated set of variable names are excluded from this auto-allow path because their value is interpreted as code, a config-file path, or a downstream-program name by the very next command in the same shell sequence — turning a benign-looking `VAR=$(echo …)` into a vector for environment-variable injection. The set covers the dynamic loader (`LD_*`, `DYLD_*`, `PATH`), git command/config injection (`GIT_SSH_COMMAND`, `GIT_CONFIG_*`, `GIT_EXTERNAL_DIFF`, …), language runtime preload (`NODE_OPTIONS`, `PYTHONPATH`, `PERL5OPT`, `RUBYOPT`, `JAVA_TOOL_OPTIONS`, `DOTNET_STARTUP_HOOKS`, …), shell-init traps (`BASH_ENV`, `ENV`, `PS4`), package-manager config namespaces (`NPM_CONFIG_*`, `PIP_*`), cloud/container redirection (`KUBECONFIG`, `AWS_CONFIG_FILE`, `DOCKER_HOST`), editors and pagers spawned by `git`/`crontab`/`man`, and glibc data-file paths (`GCONV_PATH`, `LOCPATH`, `NLSPATH`).

The full lists ship as `sensitive_env_vars` and `sensitive_env_var_prefixes` in your `config.toml` — see the [seed file](internal/config/config.toml) for the canonical baseline. Edit the lists in your own config to add or remove names; running `turnstile upgrade` merges new baseline entries into your config without overwriting your additions or formatting. Names on these lists remain `ask` unless you explicitly add them to your `allow` list (the trailing `=` on the pattern is intentional, since the auto-allow check runs on the normalized segment `NAME=__SUBSHELL__`):

```toml
allow = ['GIT_SSH_COMMAND=']
```

## How it works

Turnstile receives `{"tool_name": "...", "tool_input": {...}}` on stdin and emits `{"hookSpecificOutput": {"permissionDecision": "allow|ask|deny", ...}}` on stdout. For Bash commands, backtick subshells return `ask`, `$(...)` subshells are recursively validated, standalone variable assignments whose value is a validated subshell (`VAR=$(…)`) are auto-allowed (see [Subshell-assigned environment variables](#subshell-assigned-environment-variables)), output and input redirections return `ask` unless they target `/dev/null` or standard streams, and the command is split on `|`, `||`, `&&`, `;`, and newlines (quote-aware). Any segment that matches a `deny` pattern causes the entire command to return `deny`. All segments must match an `allow` pattern for the command to return `allow`. Otherwise, the first unrecognized token triggers `ask` with context. For non-Bash tools, the decision is `allow` if the tool name is in `tools`, otherwise `ask` (or `defer` if `tools_default_to_defer = true` is set).

The [PreToolUse hook specification](https://code.claude.com/docs/en/hooks#hookspecificoutput-pretooluse) defines four decision values: `allow`, `deny`, `ask`, and `defer`. By default, turnstile emits only three: `allow`, `deny`, and `ask`. An unrecognized non-Bash tool produces `ask` so the user is prompted exactly once and can adjust the `tools` list. Optionally, set `tools_default_to_defer = true` in your config to emit `defer` instead, letting Claude Code's [`settings.json` permission rules](https://code.claude.com/docs/en/settings#permissions) take over.

When the decision is `ask` or `deny`, the reason string follows the format `<verdict>: <feature> [: <detail>]`, where `<feature>` is one of `unknown-tool`, `empty-command`, `backtick-subshell`, `reserved-placeholder`, `unparsable-command`, `denied-pattern`, `subshell-depth`, `shell-c-pattern`, `unknown-command`, `cd-outside-roots`, `heredoc-unterminated`, `output-redirection`, `input-redirection`, `subshell-substitution`, or `process-substitution`, and `<detail>` provides additional context such as the token or pattern that triggered the decision. Examples: `ask: unknown-command: foo`, `deny: denied-pattern: sudo: sudo\b`, `ask: unknown-tool: NotebookEdit`. This format enables automated agents to parse and act on the cause of a decision.

Per the [PreToolUse hook specification](https://code.claude.com/docs/en/hooks#hookspecificoutput-pretooluse), `permissionDecisionReason` is populated for `ask` and `deny` verdicts, and `additionalContext` is populated for `allow` verdicts when there's explanatory context about why the tool call was permitted (e.g., which pattern matched).

## Performance

In-process decision logic runs in under 1ms. Total wall time per invocation is approximately 15–25ms warm (Go startup overhead), more if cold. Benchmark data and profiling details are tracked in `internal/` and will be consolidated into a dedicated `BENCHMARKS.md` in a future release.

## Claude Skill

Install the skill to let Claude manage your rules directly from conversation.

### Installation

Claude Code loads skills from `~/.claude/skills/` (user-level, available in every project) or `.claude/skills/` (project-level). From the repo root, run once:

```sh
turnstile install
```

Or manually:

```sh
mkdir -p ~/.claude/skills/turnstile
cp claude/skills/turnstile/SKILL.md ~/.claude/skills/turnstile/SKILL.md
```

Verify by typing `/turnstile` in any Claude Code session.

### Usage

```
/turnstile add allow terraform
/turnstile remove tools NotebookEdit
/turnstile upgrade
```

Claude runs the matching `turnstile` subcommand and reports the result. No config reading, no diff preview, no confirmation step.

### Permission self-service

Drop this into your `CLAUDE.md` (project or `~/.claude/CLAUDE.md`):

```markdown
When a Bash command or tool is blocked by the `turnstile` PreToolUse hook and the request is genuinely safe for this environment, run `turnstile add <section> <value>` to allow it without asking me first.

Never add entries that would allow `sudo`, privileged Docker flags, reads from credential directories (`.ssh`, `.aws`, `.gnupg`, `.claude`), `kubectl delete`, or other destructive operations. Surface the concern instead.
```

This turns "hook blocked me" into an immediate fix rather than a multi-step proposal.

## Security

Turnstile operates as a security boundary for Claude Code tool calls. Its threat model is scoped to prevent prompt-injection-driven tool calls and regex-bypass attempts. In-scope defenses include validating command structure, enforcing deny-over-allow precedence, and rejecting shell features that obscure intent (backtick subshells, unterminated heredocs, arbitrary redirections). Out-of-scope are kernel-level sandboxing, network egress filtering, and post-allow command behavior — once a command is allowed, it runs with the full privileges of the Claude Code process.

For vulnerability reporting and supported versions, see [SECURITY.md](SECURITY.md).

## Contributing

PRs welcome. Please run `make ci` before submitting and ensure tests pass. For bugs, feature requests, or questions, open an issue in the [GitHub tracker](https://github.com/rogvc/turnstile/issues).

## License

[MIT](LICENSE)
