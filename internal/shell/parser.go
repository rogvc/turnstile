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

// Builtin process-wrapper regexes — these are always stripped regardless of
// config, matching Claude Code's own native wrapper-stripping behaviour.
var (
	timeoutWrapperRE = regexp.MustCompile(`^timeout\s+\S+\s+`)
	timeWrapperRE    = regexp.MustCompile(`^time\s+`)
	niceWrapperRE    = regexp.MustCompile(`^nice(?:\s+-n\s+\S+)?\s+`)
	nohupWrapperRE   = regexp.MustCompile(`^nohup\s+`)
	stdbufWrapperRE  = regexp.MustCompile(`^stdbuf(?:\s+-[ioe]\S+)+\s+`)
	xargsWrapperRE   = regexp.MustCompile(`^xargs\s+`)
)

// StripWrappers iteratively removes leading process-wrapper prefixes from seg.
// Builtins (timeout, time, nice, nohup, stdbuf, bare xargs) are always
// stripped. extra lists additional single-command wrapper names from config.
func StripWrappers(seg string, extra []string) string {
	for {
		next := stripOneWrapper(seg, extra)
		if next == seg {
			return seg
		}
		seg = next
	}
}

func stripOneWrapper(seg string, extra []string) string {
	for _, re := range []*regexp.Regexp{
		timeoutWrapperRE, timeWrapperRE, niceWrapperRE,
		nohupWrapperRE, stdbufWrapperRE,
	} {
		if m := re.FindString(seg); m != "" {
			return seg[len(m):]
		}
	}
	// xargs: strip only when not immediately followed by a flag.
	if m := xargsWrapperRE.FindString(seg); m != "" {
		rest := seg[len(m):]
		if rest != "" && rest[0] != '-' {
			return rest
		}
	}
	for _, w := range extra {
		prefix := w + " "
		if strings.HasPrefix(seg, prefix) {
			return strings.TrimSpace(seg[len(prefix):])
		}
	}
	return seg
}

// heredocDelim holds a parsed heredoc delimiter word and whether body lines
// should have leading tabs stripped (<<- form).
type heredocDelim struct {
	word      string
	stripTabs bool
}

// ExtractHeredocs removes heredoc bodies from cmd, keeping only the opener
// lines. It returns the processed string and true when all heredocs terminated
// normally. If an unterminated heredoc is found, it returns false — the caller
// should treat the command as requiring manual review rather than silently
// dropping content.
func ExtractHeredocs(cmd string) (string, bool) {
	if !strings.Contains(cmd, "<<") {
		return cmd, true
	}
	lines := strings.Split(cmd, "\n")
	result := make([]string, 0, len(lines))
	i := 0
	for i < len(lines) {
		line := lines[i]
		delims := findHeredocDelimiters(line)
		if len(delims) == 0 {
			result = append(result, line)
			i++
			continue
		}
		// Keep the opener line, then skip the body for each heredoc.
		result = append(result, line)
		i++
		for _, d := range delims {
			terminated := false
			for i < len(lines) {
				bodyLine := lines[i]
				i++
				check := bodyLine
				if d.stripTabs {
					check = strings.TrimLeft(bodyLine, "\t")
				}
				if check == d.word {
					terminated = true
					break
				}
			}
			if !terminated {
				return strings.Join(result, "\n"), false
			}
		}
	}
	return strings.Join(result, "\n"), true
}

// findHeredocDelimiters scans a single line for <<WORD / <<-WORD / <<'WORD' /
// <<"WORD" openers (skipping quoted content and here-strings <<<). Returns all
// delimiters found in left-to-right order.
func findHeredocDelimiters(line string) []heredocDelim {
	var out []heredocDelim
	i := 0
	for i < len(line) {
		ch := line[i]
		// Skip quoted content so we don't match << inside strings.
		if ch == '\'' || ch == '"' {
			quote := ch
			i++
			for i < len(line) && line[i] != quote {
				if quote == '"' && line[i] == '\\' {
					i++
				}
				if i < len(line) {
					i++
				}
			}
			if i < len(line) {
				i++ // closing quote
			}
			continue
		}
		// Detect << but not <<<.
		if ch == '<' && i+1 < len(line) && line[i+1] == '<' {
			if i+2 < len(line) && line[i+2] == '<' {
				i += 3 // here-string <<<, skip all three
				continue
			}
			i += 2
			stripTabs := false
			if i < len(line) && line[i] == '-' {
				stripTabs = true
				i++
			}
			// Skip optional whitespace before the delimiter word.
			for i < len(line) && line[i] == ' ' {
				i++
			}
			// Parse the delimiter word, optionally quoted.
			var word string
			if i < len(line) && (line[i] == '\'' || line[i] == '"') {
				q := line[i]
				i++
				start := i
				for i < len(line) && line[i] != q {
					i++
				}
				word = line[start:i]
				if i < len(line) {
					i++ // closing quote
				}
			} else {
				start := i
				for i < len(line) && isHeredocWordChar(line[i]) {
					i++
				}
				word = line[start:i]
			}
			if word != "" {
				out = append(out, heredocDelim{word: word, stripTabs: stripTabs})
			}
			continue
		}
		i++
	}
	return out
}

func isHeredocWordChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '_'
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
