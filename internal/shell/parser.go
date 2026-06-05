// Package shell parses Bash command strings into normalized segments for
// policy evaluation: subshell extraction, quote masking, heredoc handling,
// and pipeline splitting.
package shell

import (
	"regexp"
	"strings"
)

// Exported regexes used by callers to detect shell features in raw command
// strings (env-var prefixes, comments, redirections, heredocs, arithmetic).
var (
	// EnvVarRE matches a run of NAME=value assignments at the start of a
	// segment, each followed by whitespace (so a *trailing* command exists).
	// The unquoted-value branch deliberately excludes `(` so that a bash array
	// literal `NAME=(...)` is not mistaken for `NAME=` followed by `(...)`,
	// and excludes `;` so we never grab a value across a statement boundary.
	EnvVarRE            = regexp.MustCompile(`^(\w+=(?:"[^"]*"|'[^']*'|[^\s(;]*)\s+)+`)
	CommentLineRE       = regexp.MustCompile(`(?m)^[ \t]*#[^\n]*(?:\n|$)`)
	RedirectRE          = regexp.MustCompile(`>\s*\S|>>`)
	SafeRedirectRE      = regexp.MustCompile(`(?:[12]\s*)?>\s*/dev/null\b|2\s*>\s*&\s*1|>\s*&\s*2`)
	InputRedirectRE     = regexp.MustCompile(`<\s*\S`)
	SafeInputRedirectRE = regexp.MustCompile(`<<<?|<\s*/dev/null\b`)
	HeredocRE           = regexp.MustCompile(`^[^\n]*<<`)
	ArithBodyRE         = regexp.MustCompile(`^\s*\(`)
)

// StripComments removes shell comment lines from cmd.
func StripComments(cmd string) string {
	return CommentLineRE.ReplaceAllString(cmd, "")
}

// JoinContinuations replaces line-continuation sequences (\<newline>) with a space.
func JoinContinuations(cmd string) string {
	return strings.ReplaceAll(cmd, "\\\n", " ")
}

// precededByBackslash returns true when cmd[i] is preceded by an odd number of
// consecutive backslashes (meaning the character at i is escaped).
func precededByBackslash(cmd string, i int) bool {
	count := 0
	for j := i - 1; j >= 0 && cmd[j] == '\\'; j-- {
		count++
	}
	return count%2 == 1
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
		switch {
		case ch == '\'':
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
		case ch == '$' && i+1 < len(cmd) && cmd[i+1] == '(' && !precededByBackslash(cmd, i):
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
			if depth == 0 && j > i+2 {
				bodies = append(bodies, cmd[i+2:j-1])
				b.WriteString("__SUBSHELL__")
			} else {
				// Unterminated subshell — write literal characters.
				b.WriteString(cmd[i:j])
			}
			i = j
		default:
			b.WriteByte(ch)
			i++
		}
	}
	return bodies, b.String()
}

// ExtractProcSubst returns all <(...) and >(...) bodies and the outer command
// with each occurrence replaced by __PROCSUBST__. Byte-level scan — safe for
// UTF-8 because all sentinels are ASCII and multibyte sequences never contain
// ASCII bytes.
func ExtractProcSubst(cmd string) (bodies []string, outer string) {
	if !strings.Contains(cmd, "<(") && !strings.Contains(cmd, ">(") {
		return nil, cmd
	}
	var b strings.Builder
	b.Grow(len(cmd))
	i := 0
	for i < len(cmd) {
		if i < len(cmd) && cmd[i] == '\'' {
			i = copyQuoted(cmd, i, &b)
			continue
		}
		ch := cmd[i]
		if (ch == '<' || ch == '>') && i+1 < len(cmd) && cmd[i+1] == '(' && !precededByBackslash(cmd, i) {
			i = extractProcSubstAt(cmd, i, &b, &bodies)
			continue
		}
		b.WriteByte(ch)
		i++
	}
	return bodies, b.String()
}

// copyQuoted copies a single-quoted string from cmd[i] to b and returns the
// position after the closing quote.
func copyQuoted(cmd string, i int, b *strings.Builder) int {
	b.WriteByte(cmd[i])
	i++
	for i < len(cmd) && cmd[i] != '\'' {
		b.WriteByte(cmd[i])
		i++
	}
	if i < len(cmd) {
		b.WriteByte(cmd[i])
		i++
	}
	return i
}

// extractProcSubstAt extracts a single process substitution starting at cmd[i]
// and returns the position after the closing paren.
func extractProcSubstAt(cmd string, i int, b *strings.Builder, bodies *[]string) int {
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
	if depth == 0 && j > i+2 {
		*bodies = append(*bodies, cmd[i+2:j-1])
		b.WriteString("__PROCSUBST__")
	} else {
		b.WriteString(cmd[i:j])
	}
	return j
}

// processQuotedContent handles masking of content within a quoted string.
// Returns the new position after the closing quote.
func processQuotedContent(cmd string, i int, quote byte, isANSIC bool, b *strings.Builder) int {
	b.WriteByte(quote)
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
		if isANSIC && cmd[i] == '\\' && i+1 < len(cmd) {
			next := cmd[i+1]
			if next == '\\' || next == '\'' || next == 'n' || next == 't' {
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
	return i
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
			// Check for ANSI-C string ($'...')
			isANSIC := ch == '\'' && i > 0 && cmd[i-1] == '$' && !precededByBackslash(cmd, i-1)
			i = processQuotedContent(cmd, i, ch, isANSIC, &b)
		} else {
			b.WriteByte(ch)
			i++
		}
	}
	return b.String()
}

// StripSafeRedirects rewrites every `> target`, `>> target`, `N> target`, and
// `N>> target` occurrence in cmd to a sentinel when target's source path passes
// IsSafePath against safeTargets. The masked form (quotes already replaced
// with `_`) is required so we don't trip over operators inside strings. Unsafe
// or non-matching redirects are left untouched so the existing RedirectRE
// check still catches them. Note: because the target span is replaced, deny
// patterns written against literal redirect targets (e.g. `> /tmp/foo`) won't
// match — none exist today, but adding one would silently no-op.
func StripSafeRedirects(masked string, safeTargets []string) string {
	if len(safeTargets) == 0 || !strings.ContainsRune(masked, '>') {
		return masked
	}
	var b strings.Builder
	b.Grow(len(masked))
	i := 0
	for i < len(masked) {
		if !isStripCandidate(masked, i) {
			b.WriteByte(masked[i])
			i++
			continue
		}
		next := tryStripOneRedirect(masked, i, safeTargets, &b)
		if next == i {
			b.WriteByte(masked[i])
			i++
			continue
		}
		i = next
	}
	return b.String()
}

// isStripCandidate reports whether masked[i] starts a `>` or `>>` operator
// that targets a file (i.e. not a stream-dup `>&`, not escaped).
func isStripCandidate(masked string, i int) bool {
	if masked[i] != '>' || precededByBackslash(masked, i) {
		return false
	}
	if i+1 < len(masked) && masked[i+1] == '&' {
		return false
	}
	return true
}

// tryStripOneRedirect tests whether the `>`/`>>` at masked[i] targets a safe
// path. On match it appends the sentinel to b (dropping any fd digit already
// written) and returns the index past the target. On no-match returns i.
func tryStripOneRedirect(masked string, i int, safeTargets []string, b *strings.Builder) int {
	opEnd := i + 1
	if opEnd < len(masked) && masked[opEnd] == '>' {
		opEnd++
	}
	tokStart := opEnd
	for tokStart < len(masked) && (masked[tokStart] == ' ' || masked[tokStart] == '\t') {
		tokStart++
	}
	tokEnd := tokStart
	for tokEnd < len(masked) && !isRedirectTokenBoundary(masked[tokEnd]) {
		tokEnd++
	}
	target := masked[tokStart:tokEnd]
	if target == "" || !IsSafePath(target, safeTargets) {
		return i
	}
	out := b.String()
	if n := len(out); n > 0 && out[n-1] >= '0' && out[n-1] <= '9' {
		b.Reset()
		b.WriteString(out[:n-1])
	}
	b.WriteString("__SAFE_REDIRECT__")
	return tokEnd
}

func isRedirectTokenBoundary(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '|', ';', '&', '<', '>', '(', ')':
		return true
	}
	return false
}

// skipQuotedString advances past a quoted string, handling escapes.
// Returns the new position after the closing quote.
func skipQuotedString(cmd string, i int, quote byte, isANSIC bool) int {
	i++
	for i < len(cmd) && cmd[i] != quote {
		if quote == '"' && cmd[i] == '\\' && i+1 < len(cmd) {
			i += 2
			continue
		}
		if isANSIC && cmd[i] == '\\' && i+1 < len(cmd) {
			next := cmd[i+1]
			if next == '\\' || next == '\'' || next == 'n' || next == 't' {
				i += 2
				continue
			}
		}
		i++
	}
	if i < len(cmd) {
		i++
	}
	return i
}

// FindSplitBoundaries scans cmd for pipeline delimiters (|, ||, &&, ;, \n),
// skipping content inside quotes. Returns [start, end) index pairs.
func FindSplitBoundaries(cmd string) [][2]int {
	var out [][2]int
	i := 0
	for i < len(cmd) {
		ch := cmd[i]
		if ch == '"' || ch == '\'' {
			// Check for ANSI-C string ($'...')
			isANSIC := ch == '\'' && i > 0 && cmd[i-1] == '$' && !precededByBackslash(cmd, i-1)
			i = skipQuotedString(cmd, i, ch, isANSIC)
			continue
		}
		switch ch {
		case ';', '\n':
			if precededByBackslash(cmd, i) {
				i++
				continue
			}
			out = append(out, [2]int{i, i + 1})
			i++
		case '|':
			if precededByBackslash(cmd, i) {
				i++
				continue
			}
			if i+1 < len(cmd) && cmd[i+1] == '|' {
				out = append(out, [2]int{i, i + 2})
				i += 2
			} else {
				out = append(out, [2]int{i, i + 1})
				i++
			}
		case '&':
			if precededByBackslash(cmd, i) {
				i++
				continue
			}
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

// StripExemptPaths rewrites flag+path occurrences in seg where the captured
// path is safe: starts with one of exemptPaths and contains no ".." traversal.
// Each matched occurrence is replaced with __SAFE_PATH__. flagRE must have
// exactly one capture group that captures the path or colon-separated mount
// spec (source:dest). The docker-volume scope (matching -v / --volume flags)
// is one example use case.
func StripExemptPaths(seg string, flagRE *regexp.Regexp, exemptPaths []string) string {
	if flagRE == nil || len(exemptPaths) == 0 {
		return seg
	}
	matches := flagRE.FindAllStringSubmatchIndex(seg, -1)
	if len(matches) == 0 {
		return seg
	}
	var b strings.Builder
	b.Grow(len(seg))
	pos := 0
	for _, m := range matches {
		fullStart, fullEnd := m[0], m[1]
		pathStart, pathEnd := m[2], m[3]
		b.WriteString(seg[pos:fullStart])
		if IsSafePath(seg[pathStart:pathEnd], exemptPaths) {
			b.WriteString("__SAFE_PATH__")
		} else {
			b.WriteString(seg[fullStart:pathStart])
			b.WriteString("__UNSAFE_PATH__")
		}
		pos = fullEnd
	}
	b.WriteString(seg[pos:])
	return b.String()
}

// IsSafePath returns true when the path spec's source component (left of the
// first ':') starts with an exempt prefix and contains no ".." component.
// Leading and trailing quote characters are stripped first so that both
// -v /tmp/x and -v "/tmp/x" are treated identically.
func IsSafePath(pathSpec string, exemptPaths []string) bool {
	if n := len(pathSpec); n >= 2 {
		if q := pathSpec[0]; (q == '"' || q == '\'') && pathSpec[n-1] == q {
			pathSpec = pathSpec[1 : n-1]
		}
	}
	src := strings.SplitN(pathSpec, ":", 2)[0]
	for _, part := range strings.Split(src, "/") {
		if part == ".." {
			return false
		}
	}
	for _, exempt := range exemptPaths {
		if src == exempt || strings.HasPrefix(src, exempt+"/") {
			return true
		}
	}
	return false
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
	// builtinWrapperREs is hoisted to avoid allocating a fresh slice on each
	// stripOneWrapper call. Avoids re-iteration over the slice for the common
	// no-wrapper case via fast-path prefix checks.
	builtinWrapperREs = []*regexp.Regexp{
		timeoutWrapperRE, timeWrapperRE, niceWrapperRE,
		nohupWrapperRE, stdbufWrapperRE,
	}
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

// looksLikeWrapper performs a fast byte-prefix check to short-circuit regex
// matching for the common no-wrapper case.
func looksLikeWrapper(seg string) bool {
	if len(seg) == 0 {
		return false
	}
	// Fast path: check only the first character against known wrapper prefixes.
	// Wrappers start with: timeout, time, nice, nohup, stdbuf, xargs, or user extras.
	// All builtins start with lowercase letters, so we can check the first byte.
	b := seg[0]
	return (b >= 'a' && b <= 'z') && (b == 'n' || b == 't' || b == 's' || b == 'x')
}

func stripOneWrapper(seg string, extra []string) string {
	// Fast path: if it doesn't look like a wrapper, skip expensive regex matching.
	if !looksLikeWrapper(seg) && len(extra) == 0 {
		return seg
	}

	for _, re := range builtinWrapperREs {
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
		switch {
		case ch == '\'' || ch == '"':
			i = skipQuoted(line, i)
		case ch == '<' && i+1 < len(line) && line[i+1] == '<':
			if i+2 < len(line) && line[i+2] == '<' {
				i += 3 // here-string <<<, skip all three
				continue
			}
			d, next := parseHeredocOpener(line, i+2)
			if d.word != "" {
				out = append(out, d)
			}
			i = next
		default:
			i++
		}
	}
	return out
}

// skipQuoted advances past a single- or double-quoted string starting at i.
func skipQuoted(line string, i int) int {
	quote := line[i]
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
	return i
}

// parseHeredocOpener reads the optional `-`, optional whitespace, and the
// (possibly quoted) delimiter word starting at i. Returns the parsed delimiter
// and the index after it.
func parseHeredocOpener(line string, i int) (heredocDelim, int) {
	stripTabs := false
	if i < len(line) && line[i] == '-' {
		stripTabs = true
		i++
	}
	for i < len(line) && line[i] == ' ' {
		i++
	}
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
	return heredocDelim{word: word, stripTabs: stripTabs}, i
}

func isHeredocWordChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '_'
}

// shellCPattern matches sh/bash/zsh/dash/ash followed by -c and a quoted body.
var shellCPattern = regexp.MustCompile(`\b(sh|bash|zsh|dash|ash)\s+(?:-[a-z]+\s+)*-c\s+(?:'([^']*)'|"([^"]*)")`)

// shellCPrefixPattern matches sh/bash/zsh/dash/ash followed by -c (with or without a body).
var shellCPrefixPattern = regexp.MustCompile(`\b(sh|bash|zsh|dash|ash)\s+(?:-[a-z]+\s+)*-c\b`)

// findExecPattern matches -exec[dir] ... \; or + within find commands
var findExecPattern = regexp.MustCompile(`-exec(?:dir)?\s+(.*?)\s+(?:\\;|\+)`)

// xargsShellCPattern matches xargs [options] sh/bash -c '...'
var xargsShellCPattern = regexp.MustCompile(`\bxargs\b.*?(?:sh|bash|zsh|dash|ash)\s+-c\s+(?:'([^']*)'|"([^"]*)")`)

// hereStringPattern matches interpreter <<< string patterns
var hereStringPattern = regexp.MustCompile(`^\s*(sh|bash|zsh|dash|ash)\b.*?<<<\s*(.*)`)

// ExtractShellCBody extracts all inner command bodies from "sh -c '<body>'" style
// invocations. It returns a slice of bodies found; an empty slice means no matches.
func ExtractShellCBody(seg string) []string {
	matches := shellCPattern.FindAllStringSubmatch(seg, -1)
	if len(matches) == 0 {
		return nil
	}
	bodies := make([]string, 0, len(matches))
	for _, m := range matches {
		// m[2] is single-quote body, m[3] is double-quote body; one is non-empty.
		if m[2] != "" {
			bodies = append(bodies, m[2])
		} else {
			bodies = append(bodies, m[3])
		}
	}
	return bodies
}

// HasShellCNonLiteralBody returns true when seg contains a shell -c invocation
// where the -c flag is not followed by a literal quoted string. This catches
// dangerous patterns like "bash -c $cmd" or "bash -c $(echo foo)" that bypass
// the normal shell-c recursion checks.
func HasShellCNonLiteralBody(seg string) bool {
	// First check if there's any shell -c pattern at all.
	if !shellCPrefixPattern.MatchString(seg) {
		return false
	}
	// If shellCPattern (which requires a quoted body) matches, then all -c
	// invocations have literal bodies and this check passes.
	literalMatches := shellCPattern.FindAllStringIndex(seg, -1)
	prefixMatches := shellCPrefixPattern.FindAllStringIndex(seg, -1)
	// If the counts differ, at least one -c has a non-literal body.
	return len(prefixMatches) != len(literalMatches)
}

// ExtractHereStringBody extracts the inner command body from "sh <<< 'body'"
// or "bash <<< body" patterns where the opener is an interpreter (sh/bash/zsh/
// dash/ash). It returns (body, true) when a match is found, or ("", false)
// otherwise. Only the first match is returned. The right-hand string is parsed
// respecting single quotes, double quotes, and unquoted forms.
func ExtractHereStringBody(seg string) (string, bool) {
	m := hereStringPattern.FindStringSubmatch(seg)
	if m == nil {
		return "", false
	}
	// m[1] is the interpreter, m[2] is the right-hand side after <<<
	rhs := strings.TrimSpace(m[2])
	if rhs == "" {
		return "", false
	}
	// Parse the string: single-quoted, double-quoted, or unquoted
	if rhs[0] == '\'' {
		// Single-quoted: find closing quote
		end := strings.IndexByte(rhs[1:], '\'')
		if end == -1 {
			return "", false // unterminated
		}
		return rhs[1 : end+1], true
	}
	if rhs[0] == '"' {
		// Double-quoted: find closing quote, respecting backslash escapes
		i := 1
		for i < len(rhs) {
			if rhs[i] == '"' {
				return rhs[1:i], true
			}
			if rhs[i] == '\\' && i+1 < len(rhs) {
				i += 2
				continue
			}
			i++
		}
		return "", false // unterminated
	}
	// Unquoted: take until whitespace or end
	for i := 0; i < len(rhs); i++ {
		if rhs[i] == ' ' || rhs[i] == '\t' || rhs[i] == '\n' {
			return rhs[:i], true
		}
	}
	return rhs, true
}

// ExtractFindExecBody extracts all command portions from find -exec or -execdir
// clauses. It returns a slice of bodies found; an empty slice means no matches.
func ExtractFindExecBody(seg string) []string {
	// Only process if the segment contains "find" to avoid false matches.
	if !strings.Contains(seg, "find") {
		return nil
	}
	matches := findExecPattern.FindAllStringSubmatch(seg, -1)
	if len(matches) == 0 {
		return nil
	}
	bodies := make([]string, 0, len(matches))
	for _, m := range matches {
		bodies = append(bodies, strings.TrimSpace(m[1]))
	}
	return bodies
}

// ExtractXargsShellCBody extracts all inner command bodies from xargs patterns
// that end with "sh -c '...'". It returns a slice of bodies found; an empty slice means no matches.
func ExtractXargsShellCBody(seg string) []string {
	matches := xargsShellCPattern.FindAllStringSubmatch(seg, -1)
	if len(matches) == 0 {
		return nil
	}
	bodies := make([]string, 0, len(matches))
	for _, m := range matches {
		// m[1] is single-quote body, m[2] is double-quote body.
		if m[1] != "" {
			bodies = append(bodies, m[1])
		} else {
			bodies = append(bodies, m[2])
		}
	}
	return bodies
}

// SplitPipeline splits cmd at shell pipeline boundaries and returns cleaned
// segments with env-var prefixes, comment-only entries, and blanks removed.
// A segment that starts with '-' is appended to the previous segment to handle
// flag-only pipeline components.
func SplitPipeline(cmd string) []string {
	segs, _ := SplitPipelineDetailed(cmd)
	return segs
}

// SplitPipelineDetailed is SplitPipeline plus a parallel slice of the env-var
// assignment names that prefixed each segment in the original input. The names
// slice is the same length as the segments slice; entries are nil when a
// segment had no leading assignments. Callers that need to enforce a policy
// over assignment *names* (e.g. blocking LD_PRELOAD=evil ls) consume the names
// here; callers that only care about the command itself can keep using
// SplitPipeline. A standalone NAME=value with no trailing command is left
// intact in the segment (and produces no name entry) — same as before.
func SplitPipelineDetailed(cmd string) ([]string, [][]string) {
	boundaries := FindSplitBoundaries(cmd)
	raw := make([]string, 0, len(boundaries)+1)
	prev := 0
	for _, m := range boundaries {
		raw = append(raw, cmd[prev:m[0]])
		prev = m[1]
	}
	raw = append(raw, cmd[prev:])

	segments := make([]string, 0, len(raw))
	envNames := make([][]string, 0, len(raw))
	for _, seg := range raw {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		var names []string
		if strings.Contains(seg, "=") {
			if loc := EnvVarRE.FindStringIndex(seg); loc != nil {
				names = leadingAssignNames(seg[:loc[1]])
				seg = strings.TrimSpace(seg[loc[1]:])
			}
		}
		if seg == "" || seg == "\\" {
			continue
		}
		if strings.HasPrefix(seg, "#") {
			continue
		}
		if strings.HasPrefix(seg, "(") || strings.HasPrefix(seg, "{") {
			seg = strings.TrimSpace(seg[1:])
		}
		if seg == "" {
			continue
		}
		if strings.HasSuffix(seg, ")") || strings.HasSuffix(seg, "}") {
			seg = strings.TrimSpace(seg[:len(seg)-1])
		}
		if seg == "" {
			continue
		}
		seg = StripLeadingPath(seg)
		if strings.HasPrefix(seg, "-") && len(segments) > 0 {
			segments[len(segments)-1] = segments[len(segments)-1] + " " + seg
			if len(names) > 0 {
				envNames[len(envNames)-1] = append(envNames[len(envNames)-1], names...)
			}
		} else {
			segments = append(segments, seg)
			envNames = append(envNames, names)
		}
	}
	return segments, envNames
}

// StripLeadingPath rewrites the first token of seg to its basename when the
// token is a path (contains a `/`). Bash treats any command word containing
// a slash as a direct path lookup rather than a PATH search, so the basename
// is unambiguously the program being run — `/bin/sed`, `/usr/local/bin/sed`,
// `./tools/sed`, and `tools/sed` all execute the same `sed` binary, and
// allow/deny rules written against the program name should match them all.
// Tokens without a slash are returned unchanged. The rest of seg (arguments,
// flags) is left untouched — only the leading command word is normalized.
func StripLeadingPath(seg string) string {
	if seg == "" {
		return seg
	}
	end := 0
	for end < len(seg) {
		c := seg[end]
		if c == ' ' || c == '\t' {
			break
		}
		end++
	}
	tok := seg[:end]
	slash := strings.IndexByte(tok, '/')
	if slash < 0 {
		return seg
	}
	// A leading token of the form `NAME=/some/path` is a variable assignment
	// whose value happens to contain a slash, not a path-qualified command.
	// SplitPipelineDetailed strips assignment prefixes only when followed by a
	// space (i.e. when an actual command follows); a standalone assignment
	// reaches us intact, and we must not mistake `/some/path` for a command.
	if eq := strings.IndexByte(tok, '='); eq >= 0 && eq < slash {
		return seg
	}
	// Refuse to strip when the token has shell metacharacters that would change
	// meaning if the path were collapsed (e.g. a redirection target glued to the
	// command word, or a glob). Bash splits on whitespace before glob expansion,
	// so a leading token never legitimately contains these — but if it does, we
	// leave it alone rather than guess.
	for i := 0; i < len(tok); i++ {
		c := tok[i]
		if c == '*' || c == '?' || c == '[' || c == '$' || c == '`' || c == '"' || c == '\'' {
			return seg
		}
	}
	idx := strings.LastIndexByte(tok, '/')
	base := tok[idx+1:]
	if base == "" {
		// Trailing slash on the command word (e.g. `/bin/`) — leave it alone so
		// the unknown-command path produces a sensible error.
		return seg
	}
	return base + seg[end:]
}

// leadingAssignNames extracts the variable names from a run of NAME=value
// assignments — the prefix that EnvVarRE matched. The input is guaranteed by
// EnvVarRE to be a sequence of `NAME=...` tokens separated by whitespace, where
// each value is either a quoted string or a run of non-space characters. We
// walk the prefix tokenizing on the first `=` and respecting quotes so that
// `A="foo bar" B=baz` yields ["A", "B"].
func leadingAssignNames(prefix string) []string {
	var names []string
	i := 0
	for i < len(prefix) {
		for i < len(prefix) && (prefix[i] == ' ' || prefix[i] == '\t') {
			i++
		}
		if i >= len(prefix) {
			break
		}
		nameStart := i
		for i < len(prefix) && prefix[i] != '=' {
			i++
		}
		if i >= len(prefix) {
			break
		}
		names = append(names, prefix[nameStart:i])
		i++ // skip '='
		for i < len(prefix) {
			c := prefix[i]
			if c == ' ' || c == '\t' {
				break
			}
			if c == '"' || c == '\'' {
				q := c
				i++
				for i < len(prefix) && prefix[i] != q {
					i++
				}
				if i < len(prefix) {
					i++
				}
				continue
			}
			i++
		}
	}
	return names
}
