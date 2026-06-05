# Claude Skill

Install the skill so Claude can manage your rules directly from conversation.

## Installation

Claude Code loads skills from `~/.claude/skills/` (user-level, available in every project) or `.claude/skills/` (project-level). From the repo root, run once:

```sh
turnstile install
```

Or do it manually:

```sh
mkdir -p ~/.claude/skills/turnstile
cp claude/skills/turnstile/SKILL.md ~/.claude/skills/turnstile/SKILL.md
```

Verify by typing `/turnstile` in any Claude Code session.

## Usage

```
/turnstile add allow terraform
/turnstile remove tools NotebookEdit
/turnstile upgrade
```

Claude runs the matching `turnstile` subcommand and reports the result, so there's no config reading, diff preview, or extra confirmation step.

## Permission self-service

Drop this into your `CLAUDE.md` (project or `~/.claude/CLAUDE.md`):

```markdown
When a Bash command or tool is blocked by the `turnstile` PreToolUse hook and the request is genuinely safe for this environment, run `turnstile add <section> <value>` to allow it without asking me first.

Never add entries that would allow `sudo`, privileged Docker flags, reads from credential directories (`.ssh`, `.aws`, `.gnupg`, `.claude`), `kubectl delete`, or other destructive operations. Surface the concern instead.
```

This turns "hook blocked me" into an immediate fix rather than a multi-step proposal.
