package shell

import (
	"regexp"
	"strings"
)

var (
	EnvVarRE           = regexp.MustCompile(`^(\w+=\S*\s+)+`)
	LineContinuationRE = regexp.MustCompile(`\\\n`)
	CommentLineRE      = regexp.MustCompile(`(?m)^[ \t]*#[^\n]*(?:\n|$)`)
	RedirectRE         = regexp.MustCompile(`>\s*\S|>>`)
	SafeRedirectRE     = regexp.MustCompile(`(?:[12]\s*)?>\s*/dev/null\b|2\s*>\s*&\s*1|>\s*&\s*2`)
	HeredocRE          = regexp.MustCompile(`^[^\n]*<<`)
	ArithBodyRE        = regexp.MustCompile(`^\s*\(`)
)

// StripComments removes shell comment lines from cmd.
func StripComments(cmd string) string {
	return CommentLineRE.ReplaceAllString(cmd, "")
}

// JoinContinuations replaces line-continuation sequences (\<newline>) with a space.
func JoinContinuations(cmd string) string {
	return LineContinuationRE.ReplaceAllString(cmd, " ")
}

// ExtractSubshells returns all $(...) bodies and the outer command with each
// occurrence replaced by __SUBSHELL__. Byte-level scan — safe for UTF-8 because
// all sentinels are ASCII and multibyte sequences never contain ASCII bytes.
func ExtractSubshells(cmd string) (bodies []string, outer string) {
	if !strings.Contains(cmd, "$(") && !strings.Contains(cmd, "'") {
		return nil, cmd
	}
	var b strings.Builder
	b.Grow(len(cmd))
	i := 0
	for i < len(cmd) {
		ch := cmd[i]
		if ch == '\'' {
			b.WriteByte(ch)
			i++
			for i < len(cmd) && cmd[i] != '\'' {
				b.WriteByte(cmd[i])
				i++
			}
			if i < len(cmd) {
				b.WriteByte(cmd[i])
				i++
			}
		} else if ch == '$' && i+1 < len(cmd) && cmd[i+1] == '(' {
			depth := 1
			j := i + 2
			for j < len(cmd) && depth > 0 {
				switch cmd[j] {
				case '(':
					depth++
				case ')':
					depth--
				}
				j++
			}
			bodies = append(bodies, cmd[i+2:j-1])
			b.WriteString("__SUBSHELL__")
			i = j
		} else {
			b.WriteByte(ch)
			i++
		}
	}
	return bodies, b.String()
}

// RemoveQuotedContent masks content inside single/double quotes with '_' so
// shell operators inside strings are not mistaken for command boundaries.
func RemoveQuotedContent(cmd string) string {
	if !strings.ContainsAny(cmd, `"'`) {
		return cmd
	}
	var b strings.Builder
	b.Grow(len(cmd))
	i := 0
	for i < len(cmd) {
		ch := cmd[i]
		if ch == '"' || ch == '\'' {
			quote := ch
			b.WriteByte(ch)
			i++
			for i < len(cmd) && cmd[i] != quote {
				if quote == '"' && cmd[i] == '\\' && i+1 < len(cmd) {
					next := cmd[i+1]
					if next == '"' || next == '\\' || next == '$' || next == '`' {
						b.WriteString("__")
						i += 2
						continue
					}
				}
				b.WriteByte('_')
				i++
			}
			if i < len(cmd) {
				b.WriteByte(cmd[i])
				i++
			}
		} else {
			b.WriteByte(ch)
			i++
		}
	}
	return b.String()
}

// FindSplitBoundaries scans cmd for pipeline delimiters (|, ||, &&, ;, \n),
// skipping content inside quotes. Returns [start, end) index pairs.
func FindSplitBoundaries(cmd string) [][2]int {
	var out [][2]int
	i := 0
	for i < len(cmd) {
		ch := cmd[i]
		if ch == '"' || ch == '\'' {
			quote := ch
			i++
			for i < len(cmd) && cmd[i] != quote {
				if quote == '"' && cmd[i] == '\\' && i+1 < len(cmd) {
					i += 2
					continue
				}
				i++
			}
			if i < len(cmd) {
				i++
			}
			continue
		}
		switch ch {
		case ';', '\n':
			out = append(out, [2]int{i, i + 1})
			i++
		case '|':
			if i+1 < len(cmd) && cmd[i+1] == '|' {
				out = append(out, [2]int{i, i + 2})
				i += 2
			} else {
				out = append(out, [2]int{i, i + 1})
				i++
			}
		case '&':
			if i+1 < len(cmd) && cmd[i+1] == '&' {
				out = append(out, [2]int{i, i + 2})
				i += 2
			} else {
				i++
			}
		default:
			i++
		}
	}
	return out
}

// SplitPipeline splits cmd at shell pipeline boundaries and returns cleaned
// segments with env-var prefixes, comment-only entries, and blanks removed.
// A segment that starts with '-' is appended to the previous segment to handle
// flag-only pipeline components.
func SplitPipeline(cmd string) []string {
	boundaries := FindSplitBoundaries(cmd)
	raw := make([]string, 0, len(boundaries)+1)
	prev := 0
	for _, m := range boundaries {
		raw = append(raw, cmd[prev:m[0]])
		prev = m[1]
	}
	raw = append(raw, cmd[prev:])

	segments := make([]string, 0, len(raw))
	for _, seg := range raw {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		if strings.Contains(seg, "=") {
			seg = strings.TrimSpace(EnvVarRE.ReplaceAllString(seg, ""))
		}
		if seg == "" || seg == "\\" {
			continue
		}
		if strings.HasPrefix(seg, "#") {
			continue
		}
		if strings.HasPrefix(seg, "(") {
			seg = strings.TrimSpace(seg[1:])
		}
		if seg == "" {
			continue
		}
		if strings.HasPrefix(seg, "-") && len(segments) > 0 {
			segments[len(segments)-1] = segments[len(segments)-1] + " " + seg
		} else {
			segments = append(segments, seg)
		}
	}
	return segments
}
