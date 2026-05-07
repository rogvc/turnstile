package gate

import (
	"strings"

	"github.com/rogvc/turnstile/internal/config"
	"github.com/rogvc/turnstile/internal/shell"
)

// Gate holds compiled policy rules and evaluates tool-use requests.
type Gate struct {
	cfg *config.Config
}

// New creates a Gate from a compiled Config.
func New(cfg *config.Config) *Gate {
	return &Gate{cfg: cfg}
}

// Decide returns ("allow"|"deny"|"ask", reason) for the given tool call.
func (g *Gate) Decide(tool string, input map[string]any) (string, string) {
	if tool == "Bash" {
		return g.decideBash(input)
	}
	if _, ok := g.cfg.Tools[tool]; ok {
		return "allow", ""
	}
	return "ask", "Tool not in allowlist: " + tool
}

func (g *Gate) decideBash(input map[string]any) (string, string) {
	cmd, _ := input["command"].(string)
	if cmd == "" {
		return "ask", "Empty command"
	}
	if strings.ContainsRune(cmd, '`') {
		return "ask", "Command contains backtick subshell — manual review required"
	}

	// Fast path: skip preprocessing passes when none of their trigger characters
	// are present.
	if strings.ContainsAny(cmd, "#\\$>") {
		if strings.Contains(cmd, "#") {
			cmd = shell.StripComments(cmd)
		}
		if strings.Contains(cmd, "\\\n") {
			cmd = shell.JoinContinuations(cmd)
		}
		if strings.Contains(cmd, "$(") {
			safe, depthExceeded, outer := g.safeSubshells(cmd, 0)
			if !safe {
				if depthExceeded {
					return "deny", "Subshell nesting exceeds analysis limit"
				}
				return "ask", "Command contains subshell substitution — manual review required"
			}
			cmd = outer
		}
		if strings.ContainsRune(cmd, '>') {
			stripped := shell.SafeRedirectRE.ReplaceAllString(shell.RemoveQuotedContent(cmd), "")
			if shell.RedirectRE.MatchString(stripped) {
				return "ask", "Command contains output redirection — manual review required"
			}
		}
	}

	segments := shell.SplitPipeline(cmd)
	if len(segments) == 0 {
		return "ask", "Could not parse command"
	}

	// Deny check runs over all segments before the allow check so that a denied
	// segment after an unknown one still produces "deny" rather than "ask".
	for _, seg := range segments {
		if g.cfg.DenyRE.MatchString(shell.RemoveQuotedContent(seg)) {
			return "deny", "Blocked pattern in: " + g.firstToken(seg)
		}
	}

	for _, seg := range segments {
		if !g.safe(seg) {
			return "ask", "Unrecognised command: " + g.firstToken(seg)
		}
	}
	return "allow", ""
}

// safeSubshells recursively validates all $(...) bodies in cmd. It returns
// whether cmd is safe, whether it hit the depth limit (which warrants "deny"
// rather than "ask"), and the outer command string with subshells replaced by
// __SUBSHELL__ (computed once and threaded back to avoid a second parse).
func (g *Gate) safeSubshells(cmd string, depth int) (safe bool, depthExceeded bool, outer string) {
	if depth > 5 {
		return false, true, ""
	}
	var bodies []string
	bodies, outer = shell.ExtractSubshells(cmd)
	for _, body := range bodies {
		body = strings.TrimSpace(body)
		if body == "" {
			continue
		}
		if shell.ArithBodyRE.MatchString(body) {
			if ok, exceeded, _ := g.safeSubshells(body, depth+1); !ok {
				return false, exceeded, outer
			}
			continue
		}
		// Heredocs inside subshell bodies are not validated — the interpreter
		// receives arbitrary body content that bypasses pattern matching.
		if shell.HeredocRE.MatchString(body) {
			return false, false, outer
		}
		stripped := shell.SafeRedirectRE.ReplaceAllString(shell.RemoveQuotedContent(body), "")
		if shell.RedirectRE.MatchString(stripped) {
			return false, false, outer
		}
		// Recurse first; the returned bodyOuter is body with its own subshells
		// already extracted — reuse it rather than calling ExtractSubshells again.
		ok, exceeded, bodyOuter := g.safeSubshells(body, depth+1)
		if !ok {
			return false, exceeded, outer
		}
		if !g.segmentsSafe(shell.SplitPipeline(bodyOuter)) {
			return false, false, outer
		}
	}
	return true, false, outer
}

func (g *Gate) segmentsSafe(segs []string) bool {
	for _, s := range segs {
		if s != "" && !g.safe(s) {
			return false
		}
	}
	return true
}

func (g *Gate) safe(seg string) bool {
	if g.cfg.DenyRE.MatchString(shell.RemoveQuotedContent(seg)) {
		return false
	}
	return g.cfg.AllowRE.MatchString(seg)
}

func (g *Gate) firstToken(seg string) string {
	if f := strings.Fields(seg); len(f) > 0 {
		return f[0]
	}
	return seg
}
