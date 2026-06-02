package gate

import "strings"

// Variable names listed here are NEVER auto-allowed via the
// standalone-subshell-assignment short-circuit (`VAR=$(safe-body)`), even when
// the body has passed allow-list and deny-pattern validation. The reason: the
// body is benign, but assigning the value to one of these names causes a
// downstream command in the same shell sequence to load attacker-controlled
// code, redirect to attacker-controlled config, or hand off to an
// attacker-named program — primitives the body validation can't see.
//
// Threat model: a typical developer command sequence
//
//	VAR=$(echo something); git fetch; npm install; python script.py
//
// where the next command is something the developer would normally run. If
// setting VAR= and then running that command produces RCE, library hijack,
// config injection, or credential exfiltration, the variable belongs here.
//
// Override path: add the variable explicitly to the allow list, e.g.
//
//	turnstile add allow 'GIT_SSH_COMMAND='
//
// Sources are catalogued per category below; see
// https://git-scm.com/docs/git, https://nodejs.org/api/cli.html,
// https://docs.python.org/3/using/cmdline.html and the equivalent man pages
// for each runtime.

// sensitiveEnvVars holds exact-match names. Use sensitiveEnvPrefixes for
// namespaces that grow over time (every new release of npm/pip/git adds
// options that map to fresh env vars in the same prefix).
var sensitiveEnvVars = map[string]struct{}{
	// Executable & library lookup (most LD_/DYLD_ vars are caught by the
	// prefix list below; PATH is here because it has no prefix).
	"PATH": {},

	// Git — values executed as commands or used as config sources.
	"GIT_SSH":              {},
	"GIT_SSH_COMMAND":      {},
	"GIT_EXTERNAL_DIFF":    {},
	"GIT_PAGER":            {},
	"GIT_EDITOR":           {},
	"GIT_SEQUENCE_EDITOR":  {},
	"GIT_ASKPASS":          {},
	"GIT_PROXY_COMMAND":    {},
	"GIT_CONFIG_GLOBAL":    {},
	"GIT_CONFIG_SYSTEM":    {},
	"GIT_CONFIG_COUNT":     {},
	"GIT_CONFIG_PARAMETERS": {},
	"GIT_ATTR_SOURCE":      {},

	// SSH / curl helpers.
	"SSH_ASKPASS":         {},
	"SSH_ASKPASS_REQUIRE": {},
	"CURL_HOME":           {},

	// Node.js — NODE_OPTIONS supports --require/--import (RCE on next `node`).
	"NODE_OPTIONS":        {},
	"NODE_PATH":           {},
	"NODE_EXTRA_CA_CERTS": {},

	// Python.
	"PYTHONPATH":       {},
	"PYTHONHOME":       {},
	"PYTHONUSERBASE":   {},
	"PYTHONBREAKPOINT": {},
	"PYTHONINSPECT":    {},
	"PYTHONSTARTUP":    {},

	// Perl, Ruby, PHP.
	"PERL5OPT": {},
	"PERL5LIB": {},
	"PERLLIB":  {},
	"PERL5DB":  {},
	"RUBYOPT":  {},
	"RUBYLIB":  {},
	"PHPRC":    {},

	// Java / JVM.
	"JAVA_TOOL_OPTIONS": {},
	"_JAVA_OPTIONS":     {},
	"JDK_JAVA_OPTIONS":  {},
	"CLASSPATH":         {},

	// Lua.
	"LUA_INIT":     {},
	"LUA_INIT_5_4": {},
	"LUA_PATH":     {},
	"LUA_CPATH":    {},

	// R — startup files run arbitrary R code on every R/Rscript invocation.
	"R_PROFILE":      {},
	"R_PROFILE_USER": {},
	"R_ENVIRON":      {},
	"R_ENVIRON_USER": {},
	"R_LIBS":         {},
	"R_LIBS_USER":    {},

	// .NET / CoreCLR — startup-hook & profiler vars (profiler dll loaded
	// process-wide as soon as a managed runtime starts; covered also by the
	// DOTNET_/CORECLR_ prefixes below for forward compatibility).
	"DOTNET_STARTUP_HOOKS": {},

	// Shell-init traps non-interactive bash invocations honor.
	"BASH_ENV": {},
	"ENV":      {},
	"PS4":      {},
	"ZDOTDIR":  {},
	"FPATH":    {},
	"IFS":      {},

	// Make / awk.
	"MAKEFLAGS":    {},
	"GNUMAKEFLAGS": {},
	"AWKPATH":      {},
	"AWKLIBPATH":   {},

	// Build / language tooling — config files & module proxies.
	"GOFLAGS":          {},
	"GOPROXY":          {},
	"GOENV":            {},
	"CARGO_HOME":       {},
	"RUSTUP_HOME":      {},
	"RUSTUP_TOOLCHAIN": {},

	// Cloud / container — config-file & daemon-socket redirection.
	"KUBECONFIG":                   {},
	"AWS_CONFIG_FILE":              {},
	"AWS_SHARED_CREDENTIALS_FILE":  {},
	"DOCKER_CONFIG":                {},
	"DOCKER_HOST":                  {},
	"DOCKER_CONTEXT":               {},
	"HELM_PLUGINS":                 {},

	// glibc dynamic loader / NSS / locale data — load attacker-controlled
	// data files for any libc-using program.
	"GCONV_PATH":  {},
	"LOCPATH":     {},
	"NLSPATH":     {},
	"HOSTALIASES": {},
	"TZDIR":       {},

	// Editors and pagers — invoked by git, crontab, man, less, systemctl,
	// kubectl edit, gh, etc.
	"EDITOR":          {},
	"VISUAL":          {},
	"PAGER":           {},
	"MANPAGER":        {},
	"LESSOPEN":        {},
	"LESSCLOSE":       {},
	"SYSTEMD_PAGER":   {},
	"SYSTEMD_EDITOR":  {},
	"BROWSER":         {},

	// Terminal data files — crafted entries have a long history of
	// triggering parser bugs in less/vim/top.
	"TERMINFO":      {},
	"TERMINFO_DIRS": {},
	"TERMCAP":       {},

	// GnuPG — GNUPGHOME lets gpg.conf direct keyserver-options exec-path
	// and pinentry-program at attacker binaries (affects git -S, pass, etc.).
	"GNUPGHOME": {},
}

// sensitiveEnvPrefixes catches namespaces whose membership grows with each
// release. Prefix match is intentional: every minor release of npm/pip/git
// exposes new options that map to fresh env vars in the same prefix, and an
// exact list goes stale immediately. A name beginning with any prefix here is
// excluded from the auto-allow path.
var sensitiveEnvPrefixes = []string{
	// Linux & macOS dynamic loaders — every LD_*/DYLD_* variant influences
	// loading of native code at process start.
	"LD_",
	"DYLD_",

	// .NET / CoreCLR profiler & host-config namespaces.
	"DOTNET_",
	"CORECLR_",

	// Git tracing & dynamic-config namespaces (GIT_TRACE, GIT_TRACE2,
	// GIT_TRACE2_EVENT/_PERF, GIT_CONFIG_KEY_<n>, GIT_CONFIG_VALUE_<n>).
	"GIT_TRACE",
	"GIT_CONFIG_KEY_",
	"GIT_CONFIG_VALUE_",

	// Package-manager config namespaces — a single matching key can
	// redirect index URLs, plugin paths, lifecycle scripts.
	"NPM_CONFIG_",
	"PIP_",
	"UV_",
	"POETRY_",
}

// isSensitiveEnvVar reports whether name is in sensitiveEnvVars or matches any
// entry in sensitiveEnvPrefixes.
func isSensitiveEnvVar(name string) bool {
	if _, ok := sensitiveEnvVars[name]; ok {
		return true
	}
	for _, p := range sensitiveEnvPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}
