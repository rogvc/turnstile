---
description: Propose and apply an entry to the turnstile config file.
argument-hint: <allow|deny|tools> <pattern or tool name>
allowed-tools: Read, Edit, Bash(echo:*), Bash(turnstile:*), Bash(printf:*)
---

You are helping the user extend their turnstile config file — the ruleset used by the `turnstile` PreToolUse hook.

The config file lives at `$TURNSTILE_CONFIG` if set, otherwise at the user's config dir: `~/.config/turnstile/config.toml` on Linux, `~/Library/Application Support/turnstile/config.toml` on macOS. Detect which one applies before editing.

The user's request is: **$ARGUMENTS**

## Parse the arguments

The first word of `$ARGUMENTS` is the **mode**; everything after is the **target**.

| mode    | section | purpose                                                                                                  |
| ------- | ------- | -------------------------------------------------------------------------------------------------------- |
| `allow` | `allow` | Allow a Bash command family (e.g. `terraform`, `cargo build`) without prompting.                         |
| `deny`  | `deny`  | Hard-block a Bash pattern regardless of other rules.                                                     |
| `tools` | `tools` | Allow a non-Bash tool name (e.g. `NotebookEdit`, `mcp__playwright__browser_snapshot`) without prompting. |

If the mode is missing or not one of the three, ask the user to pick one and stop.
If the target is missing, ask what to add and stop.

## Config shape

The config has three arrays. Use TOML literal strings (single quotes) for regex entries so backslashes don't need escaping: `'git\b'`, not `"git\\b"`.

- `allow` — Go RE2 regex fragments matched against the **start** of each Bash command segment.
- `deny` — Go RE2 regex fragments matched **anywhere** in any segment. Wins over `allow`.
- `tools` — literal tool names (not regexes).

## Workflow (all modes)

1. **Read the current config.** Use `Read` on the resolved config path so you can see existing entries and avoid duplicates. If the file doesn't exist, stop and tell the user to run turnstile at least once so it auto-writes the default. If a matching entry already exists, explain and stop.

2. **Draft the entry** for the chosen mode (see mode-specific rules below).

3. **Test the pattern BEFORE editing** with the turnstile binary. Keep the output for step 5.
   - For `allow`: confirm the current decision for the user's target command is `ask` or `deny`.
   - For `deny`: confirm the current decision for a command matching the pattern is `allow` or `ask` (if it were already denied, no entry is needed).
   - For `tools`: confirm the current decision for the tool is `ask` (pipe a non-Bash payload, e.g. `{"tool_name":"NotebookEdit","tool_input":{}}`).

   Example:

   ```sh
   echo '{"tool_name":"Bash","tool_input":{"command":"<user-command>"}}' | turnstile
   ```

4. **Show the user the proposed diff** as a fenced code block — the section the entry is going into, the exact line being added, and a one-sentence justification.

   ```
   <config path>

   @@ allow @@
   + 'terraform\b',

   Justification: routine infra-read command, no destructive subcommands
   warrant blanket allowing without a narrower pattern.
   ```

5. **Ask for confirmation.** Do not edit until the user says yes. Iterate if they want a narrower pattern, a different section, or additional entries.

6. **Apply the edit** with `Edit` on the config file. Preserve existing formatting — insert the new line in the section that thematically fits (e.g. a new Go tool goes near the existing `go\b` entries), keep the trailing comma, match indentation.

7. **Verify after editing.** Re-run the same test command and confirm the decision flipped (`ask`/`deny` → `allow` for `allow`; any → `deny` for `deny`; `ask` → `allow` for `tools`). If not, the pattern was wrong — revert and retry.

8. **Report** the final state: which section changed, what was added. Remind the user the change takes effect on the next tool call.

## Mode-specific rules

### `allow`

- Anchor patterns on the command name with `\b`: `'terraform\b'`, `'cargo\b'`.
- Do not include flags or generic args — the prefix match is deliberately coarse.
- If the user wants a subcommand filter (e.g. allow `cargo build` but not `cargo publish`), use `'cargo\s+(?:build|test|check)\b'`.
- **Never** add an entry that would allow `sudo`, `rm -rf /`, `chmod -R 777`, privileged Docker flags (`-v /`, `--privileged`), `kubectl delete`, `helm uninstall`, or reads from `.ssh` / `.aws` / `.gnupg` / `.claude` credential directories. If asked, surface the specific risk and stop.
- If the target is currently blocked by a `deny` entry, `allow` cannot override it. Tell the user which deny rule is catching the command; offer either `/turnstile deny` reconsideration (rarely appropriate) or a narrower allow pattern. Do not automatically weaken `deny`.

### `deny`

- Patterns match anywhere in a segment, so they're broader and more dangerous to get wrong. Quote-masked splitting means a pattern like `rm\b` will match both `rm file` and `echo 'rm file'` because the echo arg's quotes are masked for splitting but the deny scan runs on the raw segment text. Prefer narrower patterns: `rm\s+-rf\s+/`, `curl\s+.*\s+\|\s*sh`, etc.
- Escape regex metachars explicitly when matching literal characters: `\.` `\(` `\{`.
- Call out to the user if the proposed deny pattern would also block legitimate uses they haven't mentioned (e.g. `curl` used for API calls vs. `curl | sh` piped to a shell).

### `tools`

- Entries are **literal strings**, not regexes. Use the tool name verbatim as it appears in the hook input (e.g. `mcp__playwright__browser_snapshot`, not `mcp__playwright__*`).
- Do not add `Bash` — Bash goes through the full ruleset, not the `tools` fast path.
- Do not add write-capable tools (e.g. `mcp__github__merge_pull_request`, `mcp__atlassian__confluence_update_page`) without the user explicitly acknowledging that those tool calls will run without review. Read-only tools are the obvious candidates.

## Hard rules (all modes)

- Never delete or narrow a `deny` entry without the user stating in writing that they understand the risk and naming the specific incident where they want the looser rule.
- Never edit the Go source, the hook settings, or any file other than the turnstile config file as part of this skill.
- Never invoke `Bash` for anything other than the `turnstile` test command and `echo`/`printf` to feed it input.
