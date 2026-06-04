# How it works

Turnstile receives `{"tool_name": "...", "tool_input": {...}}` on stdin and emits `{"hookSpecificOutput": {"permissionDecision": "allow|ask|deny", ...}}` on stdout.

For Bash commands, backtick subshells return `ask` and `$(...)` subshells are recursively validated. Standalone variable assignments whose value is a validated subshell (`VAR=$(…)`) are auto-allowed (see [Environment-variable assignments](configuration.md#environment-variable-assignments)), and inline `NAME=value command …` prefixes are stripped before allow-list matching, with sensitive names forced to `ask`. Path-qualified leading tokens like `/bin/sed` or `./tools/jest` are reduced to their basename so allow and deny rules match by program name, and output and input redirections return `ask` unless they target `/dev/null` or standard streams. The command itself is split on `|`, `||`, `&&`, `;`, and newlines in a quote-aware fashion, so any segment that matches a `deny` pattern causes the entire command to return `deny`, and all segments must match an `allow` pattern for the command to return `allow`. Otherwise, the first unrecognized token triggers `ask` with context.

For non-Bash tools, the decision is `allow` if the tool name is in `tools`, otherwise `ask` (or `defer` if `tools_default_to_defer = true` is set).

The [PreToolUse hook specification](https://code.claude.com/docs/en/hooks#hookspecificoutput-pretooluse) defines four decision values: `allow`, `deny`, `ask`, and `defer`. By default, turnstile emits only three: `allow`, `deny`, and `ask`. An unrecognized non-Bash tool produces `ask` so the user is prompted exactly once and can adjust the `tools` list. Optionally, set `tools_default_to_defer = true` in your config to emit `defer` instead, letting Claude Code's [`settings.json` permission rules](https://code.claude.com/docs/en/settings#permissions) take over.

When the decision is `ask` or `deny`, the reason string follows the format `<verdict>: <feature> [: <detail>]`, where `<feature>` is one of `unknown-tool`, `empty-command`, `backtick-subshell`, `reserved-placeholder`, `unparsable-command`, `denied-pattern`, `subshell-depth`, `shell-c-pattern`, `unknown-command`, `cd-outside-roots`, `heredoc-unterminated`, `output-redirection`, `input-redirection`, `sensitive-env-var`, `subshell-substitution`, or `process-substitution`, and `<detail>` provides additional context such as the token or pattern that triggered the decision. Examples include `ask: unknown-command: foo`, `deny: denied-pattern: sudo: sudo\b`, `ask: sensitive-env-var: LD_PRELOAD`, and `ask: unknown-tool: NotebookEdit`. This format lets automated agents parse and act on the cause of a decision.

Per the [PreToolUse hook specification](https://code.claude.com/docs/en/hooks#hookspecificoutput-pretooluse), `permissionDecisionReason` is populated for `ask` and `deny` verdicts, and `additionalContext` is populated for `allow` verdicts when there's explanatory context about why the tool call was permitted (e.g. which pattern matched).

## Performance

In-process decision logic runs in under 1ms, and total wall time per invocation is roughly 15 to 25ms warm (mostly Go startup overhead), more if cold. Benchmark data and profiling details are tracked in `internal/` and will be consolidated into a dedicated `BENCHMARKS.md` in a future release.

## Security model

Turnstile operates as a security boundary for Claude Code tool calls, and its threat model is scoped to prevent prompt-injection-driven tool calls and regex-bypass attempts. In-scope defenses include validating command structure, enforcing deny-over-allow precedence, and rejecting shell features that obscure intent (backtick subshells, unterminated heredocs, arbitrary redirections). Out of scope are kernel-level sandboxing, network egress filtering, and post-allow command behavior, because once a command is allowed, it runs with the full privileges of the Claude Code process.

For vulnerability reporting and supported versions, see [SECURITY.md](../SECURITY.md).
