# Configuration

Turnstile resolves its config path in this order:

1. `$TURNSTILE_CONFIG`, an explicit path to a config file you manage.
2. `$XDG_CONFIG_HOME/turnstile/config.toml`, if `XDG_CONFIG_HOME` is set.
3. [`os.UserConfigDir`](https://pkg.go.dev/os#UserConfigDir)`/turnstile/config.toml`, the platform default (`~/Library/Application Support` on macOS, `%AppData%` on Windows, `~/.config` on Linux).

The first time turnstile runs and no config file exists at the resolved path, the embedded [default ruleset](../internal/config/config.toml) is written there automatically. The defaults allow a broad set of development commands and block anything destructive or credential-adjacent.

After loading, turnstile writes a compiled cache file (e.g. `config.cache.gob`) alongside the source. On subsequent invocations, if the cache is newer than the source, the cache is loaded directly so we skip TOML parsing and regex recompilation. Typical speedup is around 30 to 40 percent, and the cache is automatically invalidated when the source file is modified.

## Core arrays

There are three arrays, all [RE2 regex](https://github.com/google/re2/wiki/Syntax) fragments. Use TOML literal strings (single quotes) so backslashes don't need escaping.

```toml
allow = ['\bgit\b', '\bls\b', '\bkubectl\b', '\w+=']
deny  = ['\bsudo\b', 'rm\s+-rf\s+/', 'kubectl\s+delete\b']
tools = ["Read", "Grep", "Write", "Edit"]
```

`allow` is matched against the start of each command segment and is the allowlist for routine work. `deny` is matched anywhere in any segment, acts as an explicit block list, and wins over `allow`. `tools` contains literal tool names, not regexes.

When you use `turnstile add` to manage entries, bare command names are automatically stored with `\b` word boundaries, so `turnstile add allow git` writes `\bgit\b` rather than `git`. Writing `git` without boundaries would match any command containing those letters as a substring. If you edit the file directly, use `\b` explicitly.

Patterns are OR'd together and compiled once at startup using Go's [`regexp.Compile`](https://pkg.go.dev/regexp#Compile), so adding rules has no measurable runtime cost.

## Recipes

### Allow Terraform, block everything else by default

```toml
allow = ['terraform\b', 'git\b', 'ls\b', 'cat\b']
deny  = []
tools = ["Read", "Grep"]
```

### Block kubectl delete, allow the rest

```toml
allow = ['kubectl\b', 'git\b']
deny  = ['kubectl\s+delete\b']
tools = ["Read", "Edit"]
```

### Scoped cd roots plus a curated allowlist

```toml
allow = ['git\b', 'npm\b', 'go\b', 'make\b', 'cat\b', 'ls\b', 'find\b']
deny  = ['rm\s+-rf\b', 'sudo\b', '\bssh\b', 'curl.*\|.*sh']
tools = ["Read", "Edit", "Grep", "Write"]
project_roots = ["/home/me/work", "/home/me/projects"]
```

When `project_roots` is set, `cd` commands with absolute paths (`/...`), home-relative paths (`~...`), or parent-relative traversal (`..`) are checked against the roots. If the target does not start with a configured root, the hook returns `ask` with reason `cd-outside-roots: <path>`. Relative paths without `..` are always allowed.

Examples with `project_roots = ["/home/me/work"]`:

- `cd /home/me/work/repo && git status` allows because the path is inside the root.
- `cd /etc && cat shadow` asks because the path is outside the root.
- `cd && pwd` allows because there's no path argument.
- `cd ../../other && ls` asks because the relative `..` escapes the root.
- `cd subdir && ls` allows because the relative path has no traversal.

## Environment variable contract

When `$TURNSTILE_CONFIG` is set, the path is canonicalized with [`filepath.Clean`](https://pkg.go.dev/path/filepath#Clean) and symlinks are resolved with [`filepath.EvalSymlinks`](https://pkg.go.dev/path/filepath#EvalSymlinks). The file must already exist and be owned by the current user (UID match) so that a malicious environment can't point turnstile at a permissive config controlled by another user. If any check fails, turnstile returns an error rather than proceeding.

For the default path, turnstile seeds an empty config with safe defaults if the file doesn't exist. If the config contains an invalid regex, the hook emits `ask` with a clear reason rather than failing silently.

## Additional configuration keys

Beyond the core arrays, turnstile supports several optional keys for advanced scenarios.

### `project_roots`

This is an array of absolute directory paths. When set, it restricts `cd` commands to those paths and their subdirectories, and the recipe above has examples.

### `tools_default_to_defer`

This boolean defaults to `false`. When set to `true`, unknown non-Bash tools return `defer` instead of `ask`, so the decision is delegated to Claude Code's built-in `settings.json` permission rules. That's useful if you want turnstile to act purely as a Bash command filter and let the harness handle MCP tool prompts.

```toml
tools_default_to_defer = true
```

### `strip_wrappers`

This is a list of command prefixes to remove before validation, which is handy for wrapper utilities like `time`, `nice`, or `nohup` that don't affect command semantics but would otherwise trigger an `ask` prompt.

```toml
strip_wrappers = ["time", "nice", "nohup"]
```

With this setting, `time git status` is validated as `git status`.

### `safe_path_exemptions`

This is an array of tables defining path exemptions for deny patterns, with three fields per exemption: `scope` is a descriptive label, `flag_pattern` is an RE2 regex with one capture group extracting the path from a flag argument, and `paths` is the list of allowed path prefixes.

The main use case is permitting Docker volume mounts for `/tmp` or `/var/tmp` while still blocking other host mounts. The `flag_pattern` must capture the path in the first capture group, so turnstile can verify that captured paths match an allowed prefix and aren't directory traversals. Anything that doesn't match is rewritten to `__UNSAFE_PATH__`, which trips the deny pattern.

```toml
[[safe_path_exemptions]]
scope = "docker-tmp-mounts"
flag_pattern = '(?:-v|--volume)(?:=|\s+)([^:]+):'
paths = ["/tmp", "/var/tmp"]
```

With this exemption, `docker run -v /tmp/data:/data ubuntu` is allowed but `docker run -v /etc:/data ubuntu` is denied.

### `safe_redirect_targets`

This is a list of path prefixes whose output redirections (`>` and `>>`, including fd-prefixed forms like `2> /tmp/err`) auto-allow without prompting. A redirect target is exempted when its source component starts with one of the listed prefixes and contains no `..` traversal, mirroring the `IsSafePath` rule used by `safe_path_exemptions`. Anything else (relative paths, absolute paths outside the list, traversal) still falls through to the existing `output-redirection` ask. The default seed configures `/tmp` and `/var/tmp`, the conventional scratch directories.

```toml
safe_redirect_targets = ["/tmp", "/var/tmp"]
```

With this list, `ls > /tmp/out.txt` and `echo hi >> /var/tmp/log` are allowed, while `ls > .git/config`, `echo bad >> ~/.bashrc`, `ls > ~/.ssh/authorized_keys`, and `ls > /tmp/../etc/passwd` continue to ask. The redirect-safety check runs before deny evaluation, so a target outside the safe list always falls through to the `output-redirection` ask rather than to `denied-pattern`. A deny pattern written specifically against a safe-listed target (e.g. `> /tmp/foo`) won't match either, because the span is rewritten to a sentinel before deny patterns run on safe redirects.

### Environment-variable assignments

A common pattern in scripts is capturing a value into a variable and passing it to a subsequent command, either as a standalone assignment or inline before the command word:

```bash
VER=$(git describe --tags --abbrev=0)
ARTIFACT=$(find dist -name '*.tar.gz' | head -1)
GIT_DIR=.git/worktree FOO=bar git status
```

For standalone `VAR=$(…)` assignments, when the `$(…)` body passes subshell validation we auto-allow the segment, because the body has already been fully vetted, deny patterns have already run, and the assignment itself executes no command. The auto-allow only applies to bare `VAR=$(…)`, so `export VAR=$(…)` is treated as a regular `export` invocation and still needs an allow-list entry.

For inline `NAME=value command …` and `NAME=$(…) command …`, we strip the assignment prefix from the segment before allow-list matching so the trailing command (`git status`, `make`, …) is what gets evaluated. The deny check still runs on the full unstripped command, so `LD_PRELOAD=evil sudo ls` still hits the `sudo` deny.

A curated set of variable names is excluded from both shortcuts and forced to `ask` because their value is interpreted as code, a config-file path, or a downstream-program name by the very next command, turning a benign-looking `VAR=$(echo …)` or `NAME=… cmd` into a vector for environment-variable injection. The set covers the dynamic loader (`LD_*`, `DYLD_*`, `PATH`), git command and config injection (`GIT_SSH_COMMAND`, `GIT_CONFIG_*`, `GIT_EXTERNAL_DIFF`, …), language runtime preload (`NODE_OPTIONS`, `PYTHONPATH`, `PERL5OPT`, `RUBYOPT`, `JAVA_TOOL_OPTIONS`, `DOTNET_STARTUP_HOOKS`, …), shell-init traps (`BASH_ENV`, `ENV`, `PS4`), package-manager config namespaces (`NPM_CONFIG_*`, `PIP_*`), cloud and container redirection (`KUBECONFIG`, `AWS_CONFIG_FILE`, `DOCKER_HOST`), editors and pagers spawned by `git`/`crontab`/`man`, and glibc data-file paths (`GCONV_PATH`, `LOCPATH`, `NLSPATH`).

The full lists ship as `sensitive_env_vars` and `sensitive_env_var_prefixes` in your `config.toml`, so see the [seed file](../internal/config/config.toml) for the canonical baseline. Edit the lists in your own config to add or remove names, and running `turnstile upgrade` merges new baseline entries into your config without overwriting your additions or formatting. Names on these lists remain `ask` (with reason `sensitive-env-var: NAME`) unless you explicitly add them to your `allow` list. For the standalone `VAR=$(…)` form the segment normalizes to `NAME=__SUBSHELL__`, so the trailing `=` on the pattern is intentional:

```toml
allow = ['GIT_SSH_COMMAND=']
```

### Path-qualified commands

Bash treats any command word containing a `/` as a direct path lookup rather than a `$PATH` search, so `/bin/sed`, `/usr/local/bin/sed`, `./tools/sed`, and `tools/sed` all execute the same `sed` binary. Allow and deny rules are written against program names, so turnstile reduces the leading path-qualified token to its basename before matching, meaning `/bin/sed -i …` is evaluated as `sed -i …`. Arguments that contain `/` (file paths, regexes) are left untouched, because only the leading command word is rewritten. Tokens that contain shell metacharacters (`*`, `?`, `[`, `$`, …) are left as-is so a glob or expansion is never silently collapsed. Deny patterns continue to fire on the basename, so `/bin/sudo …` is still denied.

A leading token of the form `NAME=/some/path` is a variable assignment whose value contains a slash, not a path-qualified command, so it is left intact and evaluated as an assignment (matching against `\w+=` or a more specific allow rule). The bound program name is checked when it is actually invoked, not at the point of assignment.
