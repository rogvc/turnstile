# Turnstile

*A fast, simple, deterministic Claude Code auto-allow mode, for the masses.*

[![CI](https://img.shields.io/github/actions/workflow/status/rogvc/turnstile/ci.yml?branch=main&label=CI&logo=github)](https://github.com/rogvc/turnstile/actions)
[![Go Reference](https://pkg.go.dev/badge/github.com/rogvc/turnstile.svg)](https://pkg.go.dev/github.com/rogvc/turnstile)
[![Go Report Card](https://goreportcard.com/badge/github.com/rogvc/turnstile)](https://goreportcard.com/report/github.com/rogvc/turnstile)
[![Release](https://img.shields.io/github/v/release/rogvc/turnstile)](https://github.com/rogvc/turnstile/releases)
[![License](https://img.shields.io/github/license/rogvc/turnstile)](LICENSE)

Turnstile lets Claude Code run the safe commands you'd never bother to confirm and stops the dangerous ones before they reach the model. It's a [PreToolUse hook](https://code.claude.com/docs/en/hooks) that returns `allow`, `ask`, or `deny` from a TOML ruleset in a couple of milliseconds.

Claude Code's built-in [`permissions`](https://code.claude.com/docs/en/settings#permissions) block uses exact string matching and operates after the tool call reaches the harness. Turnstile runs at the [PreToolUse hook](https://code.claude.com/docs/en/hooks) stage with [RE2 regular expressions](https://github.com/google/re2/wiki/Syntax), gives deny precedence over allow, supports scoped `cd` roots so directory traversal is blocked, and parses Bash commands segment-by-segment so pipelines, subshells, and redirections are validated independently. That makes it easy to express policies like "allow all git commands except those that modify remote state" or "block kubectl delete anywhere in a pipeline."

## Quickstart

Install the binary:

```sh
go install github.com/rogvc/turnstile@latest
```

Wire it up:

```sh
turnstile install
```

Or manually merge this into `~/.claude/settings.json` (assuming `turnstile` is on your `PATH`):

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

Verify it's working:

```sh
turnstile --test 'git status'
# Expected: allow

turnstile --test 'sudo rm -rf /'
# Expected: deny
```

## Documentation

For everything else, see the docs directory:

- [Usage](docs/usage.md) covers managing rules, testing decisions, and the exit code contract.
- [Configuration](docs/configuration.md) covers the config file format, recipes, environment-variable assignments, and path-qualified commands.
- [Recipes](docs/recipes/) are copy-in allow blocks per ecosystem (git, python, go, containers, cloud) for the tool-agnostic baseline.
- [How it works](docs/how-it-works.md) covers the hook protocol, decision reasons, performance, and the security model.
- [Claude Skill](docs/skill.md) covers installing the `/turnstile` skill so Claude can manage rules from conversation.

## Contributing

PRs welcome. Please run `make ci` before submitting and ensure tests pass. For bugs, feature requests, or questions, open an issue in the [GitHub tracker](https://github.com/rogvc/turnstile/issues).

## License

[MIT](LICENSE)
