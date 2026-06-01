# Security Policy

## Reporting a Vulnerability

If you discover a vulnerability in turnstile, please report it privately through one of the following channels:

- **GitHub Security Advisories** (preferred): Navigate to the [Security tab](https://github.com/rogvc/turnstile/security/advisories) and click "Report a vulnerability"
- **Email**: Send details to the maintainer listed in the repository

Please include:
- A description of the vulnerability and its impact
- Steps to reproduce or proof-of-concept
- Affected versions
- Any mitigations you've identified

We aim to acknowledge reports within 48 hours and provide a fix timeline within one week.

## Out of Scope

The following are known limitations and considered out of scope for security reports:

- **Sandbox bypass after allow**: Turnstile does not sandbox commands it allows. Once a command passes the ruleset, it executes with full privileges of the Claude Code process.
- **Time-of-check-time-of-use races**: Turnstile validates command structure before execution but does not monitor filesystem or environment changes between validation and execution.
- **Regex engine limitations**: Turnstile uses [RE2](https://github.com/google/re2/wiki/Syntax), which intentionally excludes features like backreferences to prevent ReDoS. Pattern complexity is the user's responsibility.
- **Configuration tampering**: If an attacker controls `$TURNSTILE_CONFIG` or the config file itself, they can trivially bypass protections. Use filesystem permissions and environment isolation to protect the config.
- **Network egress**: Turnstile does not filter network access. An allowed command can make arbitrary network requests.

If you're unsure whether an issue is in scope, err on the side of reporting it privately.
