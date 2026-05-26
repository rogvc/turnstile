package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
)

// ResolveAndSeed returns the config path, writing the embedded default if the file is absent.
func ResolveAndSeed() (string, error) {
	path, err := resolve()
	if err != nil {
		return "", err
	}
	return path, seed(path)
}

// AddEntry adds value to section (allow, deny, or tools) in the config at path.
// Returns (true, nil) if added, (false, nil) if already present.
func AddEntry(path, section, value string) (bool, error) {
	if err := checkSection(section); err != nil {
		return false, err
	}
	if section != "tools" {
		if _, err := regexp.Compile(value); err != nil {
			return false, fmt.Errorf("invalid regex %q: %w", value, err)
		}
	}
	data, err := os.ReadFile(path) //#nosec G304 -- path is the resolved turnstile config file
	if err != nil {
		return false, err
	}
	text := string(data)
	present, err := sectionContains(text, section, value)
	if err != nil {
		return false, err
	}
	if present {
		return false, nil
	}
	newText, err := addToText(text, section, value)
	if err != nil {
		return false, err
	}
	return true, os.WriteFile(path, []byte(newText), 0o600) //#nosec G703 -- path is the resolved turnstile config file
}

// RemoveEntry removes value from section (allow, deny, or tools) in the config at path.
// Returns (true, nil) if removed, (false, nil) if not found.
func RemoveEntry(path, section, value string) (bool, error) {
	if err := checkSection(section); err != nil {
		return false, err
	}
	data, err := os.ReadFile(path) //#nosec G304 -- path is the resolved turnstile config file
	if err != nil {
		return false, err
	}
	text := string(data)
	newText, removed, err := removeFromText(text, section, value)
	if err != nil {
		return false, err
	}
	if !removed {
		return false, nil
	}
	return true, os.WriteFile(path, []byte(newText), 0o600) //#nosec G703 -- path is the resolved turnstile config file
}

func checkSection(s string) error {
	switch s {
	case "allow", "deny", "tools":
		return nil
	}
	return fmt.Errorf("unknown section %q: must be allow, deny, or tools", s)
}

// sectionContains uses TOML parsing to check whether value is in section.
// Returns an error when the config is not parseable so callers don't silently
// overwrite a malformed file.
func sectionContains(text, section, value string) (bool, error) {
	var r raw
	if _, err := toml.Decode(text, &r); err != nil {
		return false, fmt.Errorf("parse config: %w", err)
	}
	var slice []string
	switch section {
	case "allow":
		slice = r.Allow
	case "deny":
		slice = r.Deny
	case "tools":
		slice = r.Tools
	}
	for _, v := range slice {
		if v == value {
			return true, nil
		}
	}
	return false, nil
}

// addToText inserts value into section in text, preserving all existing formatting and comments.
func addToText(text, section, value string) (string, error) {
	openIdx, closeIdx, multiLine, err := findArrayBounds(text, section)
	if err != nil {
		return "", err
	}
	var quoted string
	if section == "tools" {
		quoted = `"` + value + `"`
	} else {
		quoted = `'` + value + `'`
	}
	content := strings.TrimSpace(text[openIdx+1 : closeIdx])
	if multiLine {
		return text[:closeIdx] + "  " + quoted + ",\n" + text[closeIdx:], nil
	}
	if content == "" {
		return text[:openIdx+1] + quoted + text[closeIdx:], nil
	}
	return text[:closeIdx] + ", " + quoted + text[closeIdx:], nil
}

// removeFromText removes value from section in text, preserving all other content.
func removeFromText(text, section, value string) (string, bool, error) {
	openIdx, closeIdx, multiLine, err := findArrayBounds(text, section)
	if err != nil {
		return "", false, err
	}

	if multiLine {
		between := text[openIdx+1 : closeIdx]
		lines := strings.Split(between, "\n")
		out := make([]string, 0, len(lines))
		removed := false
		for _, line := range lines {
			v, ok := lineValue(line)
			if !removed && ok && v == value {
				removed = true
				continue
			}
			out = append(out, line)
		}
		if !removed {
			return text, false, nil
		}
		return text[:openIdx+1] + strings.Join(out, "\n") + text[closeIdx:], true, nil
	}

	// Single-line: find quoted items, filter, and rejoin.
	items := inlineItems(text[openIdx+1 : closeIdx])
	out := make([]string, 0, len(items))
	removed := false
	for _, item := range items {
		inner := item[1 : len(item)-1]
		if !removed && inner == value {
			removed = true
			continue
		}
		out = append(out, item)
	}
	if !removed {
		return text, false, nil
	}
	return text[:openIdx+1] + strings.Join(out, ", ") + text[closeIdx:], true, nil
}

// sectionHeaderREs maps the three valid sections to a precompiled regex that
// matches the array opener at the start of a line.
var sectionHeaderREs = map[string]*regexp.Regexp{
	"allow": regexp.MustCompile(`(?m)^allow\s*=\s*\[`),
	"deny":  regexp.MustCompile(`(?m)^deny\s*=\s*\[`),
	"tools": regexp.MustCompile(`(?m)^tools\s*=\s*\[`),
}

// findArrayBounds locates the opening [ and closing ] for the named section in text.
func findArrayBounds(text, section string) (openIdx, closeIdx int, multiLine bool, err error) {
	re, ok := sectionHeaderREs[section]
	if !ok {
		return 0, 0, false, fmt.Errorf("unknown section %q", section)
	}
	loc := re.FindStringIndex(text)
	if loc == nil {
		return 0, 0, false, fmt.Errorf("section %q not found in config", section)
	}
	openIdx = loc[1] - 1

	inSingle := false
	inDouble := false
	depth := 0
	for i := openIdx; i < len(text); i++ {
		ch := text[i]
		switch {
		case ch == '\'' && !inDouble:
			inSingle = !inSingle
		case ch == '"' && !inSingle:
			if inDouble {
				bs := 0
				for j := i - 1; j >= openIdx && text[j] == '\\'; j-- {
					bs++
				}
				if bs%2 == 0 {
					inDouble = false
				}
			} else {
				inDouble = true
			}
		case !inSingle && !inDouble && ch == '[':
			depth++
		case !inSingle && !inDouble && ch == ']':
			depth--
			if depth == 0 {
				multiLine = strings.ContainsRune(text[openIdx:i], '\n')
				return openIdx, i, multiLine, nil
			}
		}
	}
	return 0, 0, false, fmt.Errorf("unclosed array in section %q", section)
}

// lineValue extracts the decoded string value from a TOML array entry line.
// Returns ("", false) for blank lines, comment lines, or lines without a quoted value.
func lineValue(line string) (string, bool) {
	t := strings.TrimSpace(line)
	if t == "" || strings.HasPrefix(t, "#") {
		return "", false
	}
	if strings.HasPrefix(t, "'") {
		// TOML literal string — no escape sequences.
		end := strings.Index(t[1:], "'")
		if end < 0 {
			return "", false
		}
		return t[1 : end+1], true
	}
	if strings.HasPrefix(t, `"`) {
		// TOML basic string — handle \" escape.
		end := -1
		for i := 1; i < len(t); i++ {
			if t[i] == '"' {
				bs := 0
				for j := i - 1; j >= 1 && t[j] == '\\'; j-- {
					bs++
				}
				if bs%2 == 0 {
					end = i
					break
				}
			}
		}
		if end < 0 {
			return "", false
		}
		v := t[1:end]
		// Unescape \\ and \" (the only sequences tool names and patterns use).
		v = strings.ReplaceAll(v, `\\`, "\x00")
		v = strings.ReplaceAll(v, `\"`, `"`)
		v = strings.ReplaceAll(v, "\x00", `\`)
		return v, true
	}
	return "", false
}

// inlineItems extracts all single- or double-quoted items from a TOML inline array body.
var inlineItemRE = regexp.MustCompile(`'[^']*'|"(?:[^"\\]|\\.)*"`)

func inlineItems(content string) []string {
	return inlineItemRE.FindAllString(content, -1)
}
