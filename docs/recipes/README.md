# Recipes

The shipped baseline (`internal/config/config.toml`, seeded to your config on
first run) allows only POSIX shell primitives. It stays language- and
tool-agnostic on purpose, so nothing about your stack is assumed. When you want
Claude to run a given ecosystem's commands without a prompt, copy that recipe's
entries into the `allow` array of your `config.toml` (find its path with
`turnstile version`, or use `/turnstile allow <pattern>` to add one at a time).

Each entry is an [RE2 regex](https://github.com/google/re2/wiki/Syntax) matched
against the start of every command segment, so `'git\b'` allows `git status`,
`git commit`, and the `git` in a pipeline, while deny rules still take
precedence. Add only the recipes you actually use, because every allowed
command widens what runs without confirmation.

Variable assignments (`FOO=bar`, `GH_TOKEN=… gh …`) need no entry: a standalone
assignment runs no command and is allowed structurally, and an assignment
prefixing a command is stripped before the command is matched. Sensitive names
(PATH, IFS, LD_*, and the rest of `sensitive_env_vars`) are gated regardless.

- [Version control](version-control.md) — git, gh
- [Python](python.md) — python, pip, venv, uv, pytest
- [Go](go.md) — go, gofmt, golangci-lint
- [Containers and Kubernetes](containers.md) — docker, kubectl, helm
- [Cloud and network](cloud.md) — curl, wget, aws, trivy
