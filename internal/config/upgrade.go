package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
)

// UpgradeReport describes what an Upgrade call did. Empty Added slices and a
// false Changed flag mean the user config was already up to date.
type UpgradeReport struct {
	Path                          string
	AddedSensitiveEnvVars         []string
	AddedSensitiveEnvVarPrefixes  []string
	CreatedSensitiveEnvVars       bool // section did not exist before
	CreatedSensitiveEnvVarPrefixes bool
}

// Changed reports whether Upgrade modified the config.
func (r UpgradeReport) Changed() bool {
	return len(r.AddedSensitiveEnvVars) > 0 || len(r.AddedSensitiveEnvVarPrefixes) > 0
}

// upgradableArrays lists the auto-merge sections plus the field on `raw` that
// holds them. Adding a new mergeable section means appending an entry here
// and a tiny case in mergeMissing.
var upgradableArrays = []string{"sensitive_env_vars", "sensitive_env_var_prefixes"}

func init() {
	// Register array-header regexes for the upgradable sections so addToText
	// can locate them. The base sections (allow/deny/tools) are registered as
	// literals in edit.go — keep this in sync if you add a new section there.
	for _, s := range upgradableArrays {
		if _, ok := sectionHeaderREs[s]; !ok {
			sectionHeaderREs[s] = regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(s) + `\s*=\s*\[`)
		}
	}
}

// Upgrade merges any missing entries from the embedded baseline config into
// the user's config at path, for the array sections in upgradableArrays.
// Existing entries (and the user's own additions) are preserved verbatim;
// formatting and comments outside the touched sections are not modified.
//
// Returns a report describing what was added. When the user is already up to
// date, report.Changed() is false and the file is not rewritten.
func Upgrade(path string) (UpgradeReport, error) {
	report := UpgradeReport{Path: path}

	userBytes, err := os.ReadFile(path) //#nosec G304 -- path is the resolved turnstile config file
	if err != nil {
		return report, fmt.Errorf("read %s: %w", path, err)
	}

	var user, baseline raw
	if _, err := toml.Decode(string(userBytes), &user); err != nil {
		return report, fmt.Errorf("parse %s: %w", path, err)
	}
	if _, err := toml.Decode(string(defaultConfig), &baseline); err != nil {
		return report, fmt.Errorf("parse embedded baseline: %w", err)
	}

	text := string(userBytes)
	for _, section := range upgradableArrays {
		userVals, baselineVals := pickArrays(section, &user, &baseline)
		missing := diffMissing(baselineVals, userVals)
		if len(missing) == 0 {
			continue
		}

		newText, created, err := upsertArray(text, section, missing)
		if err != nil {
			return report, fmt.Errorf("upgrade %s: %w", section, err)
		}
		text = newText
		switch section {
		case "sensitive_env_vars":
			report.AddedSensitiveEnvVars = missing
			report.CreatedSensitiveEnvVars = created
		case "sensitive_env_var_prefixes":
			report.AddedSensitiveEnvVarPrefixes = missing
			report.CreatedSensitiveEnvVarPrefixes = created
		}
	}

	if !report.Changed() {
		return report, nil
	}

	// Round-trip the merged text to make sure we did not corrupt the file.
	var verify raw
	if _, err := toml.Decode(text, &verify); err != nil {
		return report, fmt.Errorf("upgrade produced invalid TOML — file not written: %w", err)
	}

	return report, os.WriteFile(path, []byte(text), 0o600) //#nosec G703 -- path is the resolved turnstile config file
}

func pickArrays(section string, user, baseline *raw) (u, b []string) {
	switch section {
	case "sensitive_env_vars":
		return user.SensitiveEnvVars, baseline.SensitiveEnvVars
	case "sensitive_env_var_prefixes":
		return user.SensitiveEnvVarPrefixes, baseline.SensitiveEnvVarPrefixes
	}
	return nil, nil
}

// diffMissing returns the entries in baseline that are not in user, preserving
// the baseline's order (so output is deterministic and human-readable).
func diffMissing(baseline, user []string) []string {
	have := make(map[string]struct{}, len(user))
	for _, v := range user {
		have[v] = struct{}{}
	}
	var missing []string
	for _, v := range baseline {
		if _, ok := have[v]; ok {
			continue
		}
		missing = append(missing, v)
	}
	return missing
}

// upsertArray appends each value in missing to the named array in text. If the
// array does not exist, a new multi-line block is appended at the end of the
// file. Returns (newText, createdNewSection, err).
func upsertArray(text, section string, missing []string) (string, bool, error) {
	if !sectionExists(text, section) {
		return appendNewArray(text, section, missing), true, nil
	}
	for _, v := range missing {
		next, err := addToText(text, section, v)
		if err != nil {
			return "", false, err
		}
		text = next
	}
	return text, false, nil
}

func sectionExists(text, section string) bool {
	re, ok := sectionHeaderREs[section]
	if !ok {
		return false
	}
	return re.FindStringIndex(text) != nil
}

// appendNewArray writes a fresh multi-line array block at the end of text.
// The block uses single-quoted entries so values containing regex
// metacharacters round-trip without escaping (matching the seed config style).
func appendNewArray(text, section string, values []string) string {
	var b strings.Builder
	b.WriteString(strings.TrimRight(text, "\n"))
	b.WriteString("\n\n")
	b.WriteString(section)
	b.WriteString(" = [\n")
	for _, v := range values {
		b.WriteString("  '")
		b.WriteString(v)
		b.WriteString("',\n")
	}
	b.WriteString("]\n")
	return b.String()
}
