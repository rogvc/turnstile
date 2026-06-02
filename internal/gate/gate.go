// Package gate evaluates tool-use requests against compiled allow/deny rules.
package gate

import (
	"regexp"
	"strings"

	"github.com/rogvc/turnstile/internal/config"
	"github.com/rogvc/turnstile/internal/shell"
)

// Gate holds compiled policy rules and evaluates tool-use requests.
type Gate struct {
	cfg           *config.Config
	hasExemptions bool // fast-path: skip exemption loop when none are configured
}

// subshellVerdict is a tri-state for subshell validation results.
type subshellVerdict int

const (
	subshellOK subshellVerdict = iota
	subshellUnknown
	subshellDenied
)

var standaloneSubshellAssignRE = regexp.MustCompile(`^([A-Za-z_]\w*)=(?:__SUBSHELL__|"__SUBSHELL__")$`)

// isStandaloneSubshellAssignment reports whether norm is a bare variable
// assignment whose value is the validated subshell placeholder and whose name
// is not flagged by g.isSensitiveEnvVar. When true, the caller may skip the
// allow-list check: the subshell body was already vetted by safeSubshells and
// deny patterns have already been checked; the assignment itself runs no
// command. The sensitive-name lists are read from the user's config.toml
// (sensitive_env_vars and sensitive_env_var_prefixes); see the seed config
// for the curated baseline.
func (g *Gate) isStandaloneSubshellAssignment(norm string) bool {
	m := standaloneSubshellAssignRE.FindStringSubmatch(norm)
	if m == nil {
		return false
	}
	return !g.isSensitiveEnvVar(m[1])
}

// isSensitiveEnvVar reports whether name is in the configured exact-match
// set or matches any configured prefix.
func (g *Gate) isSensitiveEnvVar(name string) bool {
	if _, ok := g.cfg.SensitiveEnvVars[name]; ok {
		return true
	}
	for _, p := range g.cfg.SensitiveEnvVarPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// New creates a Gate from a compiled Config.
func New(cfg *config.Config) *Gate {
	return &Gate{
		cfg:           cfg,
		hasExemptions: len(cfg.SafePathExemptions) > 0,
	}
}

// segNorm caches the per-segment normalization passes so they run once and
// are reused across the deny and allow checks.
type segNorm struct {
	norm   string // after path exemptions + wrapper stripping
	masked string // after RemoveQuotedContent(norm)
}

// Decide returns ("allow"|"deny"|"ask"|"defer", reason) for the given tool call.
func (g *Gate) Decide(tool string, input map[string]any) (string, string) {
	if tool == "Bash" {
		return g.decideBash(input)
	}
	if _, ok := g.cfg.Tools[tool]; ok {
		return "allow", ""
	}
	if g.cfg.ToolsDefaultToDefer {
		return "defer", ""
	}
	return "ask", "ask: unknown-tool: " + tool
}

func (g *Gate) decideBash(input map[string]any) (string, string) {
	cmd, _ := input["command"].(string)
	if cmd == "" {
		return "ask", "ask: empty-command"
	}
	if strings.ContainsRune(cmd, '`') {
		return "ask", "ask: backtick-subshell"
	}
	if strings.Contains(cmd, "__SUBSHELL__") {
		return "ask", "ask: reserved-placeholder"
	}
	if strings.Contains(cmd, "__PROCSUBST__") {
		return "ask", "ask: reserved-placeholder"
	}

	// Preprocess: strip comments, continuations, validate/extract subshells and
	// process substitutions, extract heredocs, check redirects.
	processed, hasInputRedirect, decision, reason := g.preprocessCommand(cmd)
	if decision != "" {
		return decision, reason
	}
	cmd = processed

	// Normalize full command (apply exemptions, strip wrappers) before checking
	// deny patterns, so patterns containing pipes can match the full command.
	fullNorm := g.normalizeSegment(cmd)
	fullMasked := shell.RemoveQuotedContent(fullNorm)
	if denied, pattern := g.isDenied(fullMasked); denied {
		return g.denyPatternReason(fullNorm, pattern)
	}

	segments := shell.SplitPipeline(cmd)
	if len(segments) == 0 {
		return "ask", "ask: unparsable-command"
	}

	// When ProjectRoots is configured, validate cd commands with absolute paths.
	if decision, reason := g.checkCdSegments(segments); decision != "" {
		return decision, reason
	}

	normed := g.normalizeAll(segments)

	// Check for shell -c / find -exec / xargs patterns that smuggle inner commands.
	// The recursion happens before deny/allow checks so that nested bodies are
	// validated before evaluating the outer segment.
	verdict, depthExceeded, offendingSeg, denyPattern := g.checkShellCRecursion(normed, 0)
	if verdict == subshellDenied {
		return g.denyPatternReason(offendingSeg, denyPattern)
	}
	if depthExceeded {
		return "deny", "deny: subshell-depth"
	}
	if verdict == subshellUnknown {
		return "ask", "ask: shell-c-pattern"
	}

	// Deny check runs over all segments before the allow check so that a denied
	// segment after an unknown one still produces "deny" rather than "ask".
	for _, n := range normed {
		if denied, pattern := g.isDenied(n.masked); denied {
			return g.denyPatternReason(n.norm, pattern)
		}
	}

	// After deny check, return ask if input redirection was detected.
	if hasInputRedirect {
		return "ask", "ask: input-redirection"
	}

	for _, n := range normed {
		if g.isStandaloneSubshellAssignment(n.norm) {
			continue
		}
		if !g.allowedNorm(n) {
			return "ask", "ask: unknown-command: " + g.firstToken(n.norm)
		}
	}
	return "allow", ""
}

// checkCdSegments validates cd commands in segments when ProjectRoots is configured.
// Returns ("", "") if all cd commands are safe or ProjectRoots is empty, or
// ("ask", reason) if any cd targets a path outside all project roots.
func (g *Gate) checkCdSegments(segments []string) (string, string) {
	if len(g.cfg.ProjectRoots) == 0 {
		return "", ""
	}
	for _, seg := range segments {
		fields := strings.Fields(seg)
		if len(fields) < 2 || fields[0] != "cd" {
			continue
		}
		path, ok := cdPathArg(fields)
		if !ok {
			continue
		}
		if needsRootCheck(path) && !shell.IsSafePath(path, g.cfg.ProjectRoots) {
			return "ask", "ask: cd-outside-roots: " + path
		}
	}
	return "", ""
}

// cdPathArg returns the first non-flag argument after `cd`, skipping `-P`,
// `-L`, `-e`, `--`, and any other `-x` flag (but not the bare `-` previous-dir
// shorthand). Returns ok=false when no path argument is present.
func cdPathArg(fields []string) (string, bool) {
	for i := 1; i < len(fields); i++ {
		arg := fields[i]
		if arg == "-P" || arg == "-L" || arg == "-e" || arg == "--" {
			continue
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			continue
		}
		return arg, true
	}
	return "", false
}

// needsRootCheck reports whether a cd path argument should be validated
// against project roots. Literal relative paths (only safe characters, not
// rooted at /, ~, or ..) are exempt; everything else — absolute, home-rel,
// parent-rel, or anything containing shell metacharacters — must be checked.
func needsRootCheck(path string) bool {
	if strings.HasPrefix(path, "/") || strings.HasPrefix(path, "~") || strings.HasPrefix(path, "..") {
		return true
	}
	for _, ch := range path {
		if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
			(ch >= '0' && ch <= '9') || ch == '_' || ch == '.' ||
			ch == '/' || ch == '-' {
			continue
		}
		return true
	}
	return false
}

// preprocessCommand applies all preprocessing passes to cmd: strip comments and
// continuations, validate/extract subshells and process substitutions, extract
// heredocs, and check redirects. Returns (processed, hasInputRedirect, "", "")
// on success or ("", false, decision, reason) on failure. Input-redirection
// detection is deferred so credential-deny patterns still fire on
// `cat < ~/.ssh/id_rsa`.
func (g *Gate) preprocessCommand(cmd string) (processed string, hasInputRedirect bool, decision string, reason string) {
	// Fast path: skip preprocessing passes when none of their trigger characters
	// are present.
	if !strings.ContainsAny(cmd, "#\\$><") {
		return cmd, false, "", ""
	}
	if strings.Contains(cmd, "#") {
		cmd = shell.StripComments(cmd)
	}
	if strings.Contains(cmd, "\\\n") {
		cmd = shell.JoinContinuations(cmd)
	}
	if strings.Contains(cmd, "$(") {
		var outer string
		outer, decision, reason = g.checkSubshells(cmd)
		if decision != "" {
			return "", false, decision, reason
		}
		cmd = outer
	}
	if strings.Contains(cmd, "<(") || strings.Contains(cmd, ">(") {
		var outer string
		outer, decision, reason = g.checkProcSubst(cmd)
		if decision != "" {
			return "", false, decision, reason
		}
		cmd = outer
	}
	if strings.Contains(cmd, "<<") {
		var ok bool
		cmd, ok = shell.ExtractHeredocs(cmd)
		if !ok {
			return "", false, "ask", "ask: heredoc-unterminated"
		}
	}
	if strings.ContainsRune(cmd, '>') {
		stripped := shell.SafeRedirectRE.ReplaceAllString(shell.RemoveQuotedContent(cmd), "")
		if shell.RedirectRE.MatchString(stripped) {
			return "", false, "ask", "ask: output-redirection"
		}
	}
	// Input redirection check runs after heredoc extraction since << contains <.
	if strings.ContainsRune(cmd, '<') {
		stripped := shell.SafeInputRedirectRE.ReplaceAllString(shell.RemoveQuotedContent(cmd), "")
		if shell.InputRedirectRE.MatchString(stripped) {
			hasInputRedirect = true
		}
	}
	return cmd, hasInputRedirect, "", ""
}

// checkSubshells validates subshell substitutions in cmd and returns either
// (outer, "", "") on success or ("", decision, reason) on failure.
func (g *Gate) checkSubshells(cmd string) (outer string, decision string, reason string) {
	verdict, depthExceeded, outerCmd, offendingSeg, denyPattern := g.safeSubshells(cmd, 0)
	if verdict == subshellOK {
		return outerCmd, "", ""
	}
	if depthExceeded {
		return "", "deny", "deny: subshell-depth"
	}
	if verdict == subshellDenied {
		_, reason := g.denyPatternReason(offendingSeg, denyPattern)
		return "", "deny", reason
	}
	return "", "ask", "ask: subshell-substitution"
}

// checkProcSubst validates process substitutions in cmd and returns either
// (outer, "", "") on success or ("", decision, reason) on failure.
func (g *Gate) checkProcSubst(cmd string) (outer string, decision string, reason string) {
	verdict, depthExceeded, outerCmd, offendingSeg, denyPattern := g.safeProcSubst(cmd, 0)
	if verdict == subshellOK {
		return outerCmd, "", ""
	}
	if depthExceeded {
		return "", "deny", "deny: subshell-depth"
	}
	if verdict == subshellDenied {
		_, reason := g.denyPatternReason(offendingSeg, denyPattern)
		return "", "deny", reason
	}
	return "", "ask", "ask: process-substitution"
}

// safeSubshells recursively validates all $(...) bodies in cmd. It returns
// a verdict (OK/Unknown/Denied), whether it hit the depth limit (which warrants
// "deny" rather than "ask"), the outer command string with subshells replaced by
// __SUBSHELL__ (computed once and threaded back to avoid a second parse), the
// offending segment if denied, and the deny pattern if a deny verdict was reached.
func (g *Gate) safeSubshells(cmd string, depth int) (verdict subshellVerdict, depthExceeded bool, outer string, offendingSeg string, denyPattern string) {
	if depth > 5 {
		return subshellUnknown, true, "", "", ""
	}
	var bodies []string
	bodies, outer = shell.ExtractSubshells(cmd)
	for _, body := range bodies {
		body = strings.TrimSpace(body)
		if body == "" {
			continue
		}
		if strings.Contains(body, "#") {
			body = shell.StripComments(body)
		}
		if strings.Contains(body, "\\\n") {
			body = shell.JoinContinuations(body)
		}
		// printf '%b' interprets backslash escapes at runtime, making the final
		// string opaque. Mark such subshells unsafe (force ask).
		if g.firstToken(body) == "printf" && strings.Contains(body, "%b") {
			return subshellUnknown, false, outer, "", ""
		}
		if shell.ArithBodyRE.MatchString(body) {
			v, exceeded, _, seg, pattern := g.safeSubshells(body, depth+1)
			if v != subshellOK {
				return v, exceeded, outer, seg, pattern
			}
			continue
		}
		// Strip heredoc bodies the same way the outer pass does. The opener line
		// is still pattern-checked; safety of the body itself depends on the
		// opener being allow-listed (e.g. cat is fine, bash <<EOF is not).
		if shell.HeredocRE.MatchString(body) {
			stripped, ok := shell.ExtractHeredocs(body)
			if !ok {
				return subshellUnknown, false, outer, "", ""
			}
			body = stripped
		}
		bodyMasked := shell.RemoveQuotedContent(body)
		stripped := shell.SafeRedirectRE.ReplaceAllString(bodyMasked, "")
		if shell.RedirectRE.MatchString(stripped) {
			return subshellUnknown, false, outer, "", ""
		}
		stripped = shell.SafeInputRedirectRE.ReplaceAllString(bodyMasked, "")
		if shell.InputRedirectRE.MatchString(stripped) {
			return subshellUnknown, false, outer, "", ""
		}
		// Recurse first; the returned bodyOuter is body with its own subshells
		// already extracted — reuse it rather than calling ExtractSubshells again.
		v, exceeded, bodyOuter, seg, pattern := g.safeSubshells(body, depth+1)
		if v != subshellOK {
			return v, exceeded, outer, seg, pattern
		}
		v, seg, pattern = g.segmentsSafe(shell.SplitPipeline(bodyOuter))
		if v != subshellOK {
			return v, false, outer, seg, pattern
		}
	}
	return subshellOK, false, outer, "", ""
}

// safeProcSubst recursively validates all <(...) and >(...) bodies in cmd. It
// returns a verdict (OK/Unknown/Denied), whether it hit the depth limit (which
// warrants "deny" rather than "ask"), the outer command string with process
// substitutions replaced by __PROCSUBST__ (computed once and threaded back to
// avoid a second parse), the offending segment if denied, and the deny pattern
// if a deny verdict was reached.
func (g *Gate) safeProcSubst(cmd string, depth int) (verdict subshellVerdict, depthExceeded bool, outer string, offendingSeg string, denyPattern string) {
	if depth > 5 {
		return subshellUnknown, true, "", "", ""
	}
	var bodies []string
	bodies, outer = shell.ExtractProcSubst(cmd)
	for _, body := range bodies {
		body = strings.TrimSpace(body)
		if body == "" {
			continue
		}
		// Strip heredoc bodies the same way the outer pass does.
		if shell.HeredocRE.MatchString(body) {
			stripped, ok := shell.ExtractHeredocs(body)
			if !ok {
				return subshellUnknown, false, outer, "", ""
			}
			body = stripped
		}
		stripped := shell.SafeRedirectRE.ReplaceAllString(shell.RemoveQuotedContent(body), "")
		if shell.RedirectRE.MatchString(stripped) {
			return subshellUnknown, false, outer, "", ""
		}
		// Recurse into nested $(...), <(...), and >(...).
		if strings.Contains(body, "$(") {
			v, exceeded, bodyOuter, seg, pattern := g.safeSubshells(body, depth+1)
			if v != subshellOK {
				return v, exceeded, outer, seg, pattern
			}
			body = bodyOuter
		}
		if strings.Contains(body, "<(") || strings.Contains(body, ">(") {
			v, exceeded, bodyOuter, seg, pattern := g.safeProcSubst(body, depth+1)
			if v != subshellOK {
				return v, exceeded, outer, seg, pattern
			}
			body = bodyOuter
		}
		v, seg, pattern := g.segmentsSafe(shell.SplitPipeline(body))
		if v != subshellOK {
			return v, false, outer, seg, pattern
		}
	}
	return subshellOK, false, outer, "", ""
}

// checkShellCRecursion scans normalized segments for sh -c, find -exec, and
// xargs patterns, extracting and recursively validating the inner command bodies.
// Returns (verdict, depthExceeded, offendingSeg, denyPattern).
func (g *Gate) checkShellCRecursion(normed []segNorm, depth int) (verdict subshellVerdict, depthExceeded bool, offendingSeg string, denyPattern string) {
	if depth > 5 {
		return subshellUnknown, true, "", ""
	}

	for _, n := range normed {
		// Check for shell -c with non-literal body (e.g., bash -c $cmd).
		if shell.HasShellCNonLiteralBody(n.norm) {
			return subshellUnknown, false, "", ""
		}

		// Try sh -c pattern
		bodies := shell.ExtractShellCBody(n.norm)
		for _, body := range bodies {
			body = strings.TrimSpace(body)
			if body == "" {
				continue
			}
			v, exceeded, seg, pattern := g.validateShellCBody(body, depth+1)
			if v != subshellOK {
				return v, exceeded, seg, pattern
			}
		}
		if len(bodies) > 0 {
			continue
		}

		// Try find -exec pattern
		bodies = shell.ExtractFindExecBody(n.norm)
		for _, body := range bodies {
			body = strings.TrimSpace(body)
			if body == "" {
				continue
			}
			v, exceeded, seg, pattern := g.validateShellCBody(body, depth+1)
			if v != subshellOK {
				return v, exceeded, seg, pattern
			}
		}
		if len(bodies) > 0 {
			continue
		}

		// Try xargs sh -c pattern
		bodies = shell.ExtractXargsShellCBody(n.norm)
		for _, body := range bodies {
			body = strings.TrimSpace(body)
			if body == "" {
				continue
			}
			v, exceeded, seg, pattern := g.validateShellCBody(body, depth+1)
			if v != subshellOK {
				return v, exceeded, seg, pattern
			}
		}
		if len(bodies) > 0 {
			continue
		}

		// Try here-string with interpreter pattern
		if body, ok := shell.ExtractHereStringBody(n.norm); ok {
			body = strings.TrimSpace(body)
			if body == "" {
				continue
			}
			v, exceeded, seg, pattern := g.validateShellCBody(body, depth+1)
			if v != subshellOK {
				return v, exceeded, seg, pattern
			}
			continue
		}
	}
	return subshellOK, false, "", ""
}

// validateShellCBody validates a command body extracted from sh -c, find -exec,
// or xargs patterns. It splits the body into segments, checks for nested sh -c
// recursion, and validates all segments. Returns (verdict, depthExceeded,
// offendingSeg, denyPattern).
func (g *Gate) validateShellCBody(body string, depth int) (verdict subshellVerdict, depthExceeded bool, offendingSeg string, denyPattern string) {
	if depth > 5 {
		return subshellUnknown, true, "", ""
	}

	// Split the body into segments.
	segments := shell.SplitPipeline(body)
	if len(segments) == 0 {
		return subshellOK, false, "", ""
	}

	// Normalize all segments.
	normed := g.normalizeAll(segments)

	// Recursively check for nested sh -c patterns.
	v, exceeded, seg, pattern := g.checkShellCRecursion(normed, depth)
	if v != subshellOK {
		return v, exceeded, seg, pattern
	}

	// Validate all segments.
	v, seg, pattern = g.segmentsSafe(segments)
	if v != subshellOK {
		return v, false, seg, pattern
	}

	return subshellOK, false, "", ""
}

func (g *Gate) segmentsSafe(segs []string) (subshellVerdict, string, string) {
	for _, s := range segs {
		if s != "" {
			v, normSeg, pattern := g.safeSeg(s)
			if v != subshellOK {
				return v, normSeg, pattern
			}
		}
	}
	return subshellOK, "", ""
}

func (g *Gate) normalizeAll(segments []string) []segNorm {
	out := make([]segNorm, len(segments))
	for i, seg := range segments {
		norm := g.normalizeSegment(seg)
		out[i] = segNorm{norm: norm, masked: shell.RemoveQuotedContent(norm)}
	}
	return out
}

func (g *Gate) normalizeSegment(seg string) string {
	if g.hasExemptions {
		for _, ex := range g.cfg.SafePathExemptions {
			seg = shell.StripExemptPaths(seg, ex.FlagRE, ex.Paths)
		}
	}
	return shell.StripWrappers(seg, g.cfg.StripWrappers)
}

func (g *Gate) allowedNorm(n segNorm) bool {
	return g.cfg.AllowRE.MatchString(n.norm)
}

// safeSeg is used by segmentsSafe for subshell body validation; it normalizes
// its own segment rather than relying on a pre-computed batch. It returns a
// verdict, the normalized segment (for error reporting), and the matched deny
// pattern if applicable.
func (g *Gate) safeSeg(seg string) (subshellVerdict, string, string) {
	norm := g.normalizeSegment(seg)
	masked := shell.RemoveQuotedContent(norm)
	if denied, pattern := g.isDenied(masked); denied {
		return subshellDenied, norm, pattern
	}
	if g.cfg.AllowRE.MatchString(norm) {
		return subshellOK, norm, ""
	}
	return subshellUnknown, norm, ""
}

// isDenied returns (true, pattern) when masked matches any deny entry.
// It uses the combined alternation for fast matching, then falls back to per-pattern
// matching to extract which specific pattern fired for the error message.
func (g *Gate) isDenied(masked string) (bool, string) {
	// Fast path: check the combined alternation first
	if g.cfg.DenyRE == nil || !g.cfg.DenyRE.MatchString(masked) {
		return false, ""
	}
	// Slow path: find which specific pattern matched for the error message
	for _, re := range g.cfg.DenyREs {
		if re.MatchString(masked) {
			return true, re.String()
		}
	}
	// Should never reach here if DenyRE and DenyREs are in sync
	return true, ""
}

func (g *Gate) firstToken(seg string) string {
	if f := strings.Fields(seg); len(f) > 0 {
		return f[0]
	}
	return seg
}

func (g *Gate) denyPatternReason(seg, pattern string) (string, string) {
	reason := "deny: denied-pattern: " + g.firstToken(seg)
	if pattern != "" {
		reason += ": " + pattern
	}
	return "deny", reason
}
