// Package main is the turnstile CLI entry point: it serves as a Claude Code
// PreToolUse hook by default, with `add`, `remove`, `install`, `uninstall`, and `version` subcommands.
package main

import (
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/rogvc/turnstile/internal/config"
	"github.com/rogvc/turnstile/internal/gate"
)

// This is to be set at compile time.
var version = "dev"

//go:embed claude/skills/turnstile/SKILL.md
var skillMD string

func main() {
	if len(os.Args) < 2 {
		RunHook(os.Stdin, os.Stdout, os.Stderr, os.Exit)
		return
	}
	switch os.Args[1] {
	case "version", "--version", "-v":
		fmt.Println(version)
	case "add", "remove":
		if err := runEdit(os.Args[1], os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "upgrade":
		if err := runUpgrade(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "install":
		if err := runInstall(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "uninstall":
		if err := runUninstall(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "--test", "-t":
		runTest(os.Args[2:])
	default:
		RunHook(os.Stdin, os.Stdout, os.Stderr, os.Exit)
	}
}

// RunHook executes the PreToolUse hook logic with provided I/O streams and exit handler.
func RunHook(stdin io.Reader, stdout, stderr io.Writer, exit func(int)) {
	cfg, err := config.Load()
	if err != nil {
		// Emit ask (not deny) with a short reason, and write detail to stderr.
		// Redact any paths from the error message before writing to stderr.
		errMsg := err.Error()
		// Simple path redaction: remove anything that looks like a filesystem path.
		// Paths typically contain / or \ and are often absolute (start with / on Unix or C:\ on Windows).
		redacted := strings.ReplaceAll(errMsg, config.ResolvedPath(), "[config-path]")
		_, _ = fmt.Fprintln(stderr, "turnstile: config error:", redacted)
		emit(stdout, "ask", "config-error: check stderr for details")
		exit(0)
		return
	}
	var data hookInput
	if err := json.NewDecoder(stdin).Decode(&data); err != nil {
		// Emit ask with consistent reason format (mirrors config error handling).
		_, _ = fmt.Fprintln(stderr, "turnstile: parse error:", err)
		emit(stdout, "ask", "stdin-error: see stderr")
		exit(0)
		return
	}
	if data.HookEventName != "" && data.HookEventName != "PreToolUse" {
		_, _ = fmt.Fprintln(stderr, "unsupported hook event:", data.HookEventName)
		exit(2)
		return
	}
	decision, reason := gate.New(cfg).Decide(data.ToolName, data.ToolInput)
	emit(stdout, decision, reason)
	exit(0)
}

func runEdit(cmd string, args []string) error {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), "usage: turnstile %s <section> <value>\n  section: allow, deny, or tools\n", cmd)
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		fs.Usage()
		return fmt.Errorf("expected <section> <value>, got %d arg(s)", fs.NArg())
	}
	section := fs.Arg(0)
	value := fs.Arg(1)

	path, err := config.ResolveAndSeed()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	// Determine the display value using the canonical form (same transformation
	// AddEntry/RemoveEntry will apply). Check for "tool"/"tools" case-insensitively
	// since normalizeSection hasn't run yet; everything else is a regex section.
	sectionLower := strings.ToLower(section)
	isTools := sectionLower == "tools" || sectionLower == "tool"
	var canonical string
	if isTools {
		canonical = value
	} else {
		canonical = config.Canonicalize("allow", value)
	}
	display := `"` + canonical + `"`
	if !isTools {
		display = `'` + canonical + `'`
	}

	switch cmd {
	case "add":
		return runAdd(path, section, value, display)
	case "remove":
		return runRemove(path, section, value, display)
	}
	return nil
}

func runAdd(path, section, value, display string) error {
	added, err := config.AddEntry(path, section, value)
	if err != nil {
		return err
	}
	if added {
		fmt.Printf("added %s to %s in %s\n", display, section, path)
	} else {
		fmt.Printf("%s already contains %s\n", section, display)
	}
	return nil
}

func runRemove(path, section, value, display string) error {
	removed, err := config.RemoveEntry(path, section, value)
	if err != nil {
		return err
	}
	if removed {
		fmt.Printf("removed %s from %s in %s\n", display, section, path)
	} else {
		fmt.Printf("%s does not contain %s\n", section, display)
	}
	return nil
}

func runUpgrade(args []string) error {
	fs := flag.NewFlagSet("upgrade", flag.ContinueOnError)
	fs.Usage = func() {
		_, _ = fmt.Fprintln(fs.Output(), "usage: turnstile upgrade")
		_, _ = fmt.Fprintln(fs.Output(), "\nMerges any new entries from the embedded baseline into your config.toml.")
		_, _ = fmt.Fprintln(fs.Output(), "Existing entries and your own additions are preserved.")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return fmt.Errorf("upgrade takes no positional arguments")
	}

	path, err := config.ResolveAndSeed()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	report, err := config.Upgrade(path)
	if err != nil {
		return err
	}
	if !report.Changed() {
		fmt.Printf("config at %s is already up to date\n", report.Path)
		return nil
	}

	fmt.Printf("upgraded %s:\n", report.Path)
	if len(report.AddedSensitiveEnvVars) > 0 {
		verb := "added to sensitive_env_vars"
		if report.CreatedSensitiveEnvVars {
			verb = "created sensitive_env_vars with"
		}
		fmt.Printf("  - %s %d entr%s: %s\n", verb,
			len(report.AddedSensitiveEnvVars), pluralY(len(report.AddedSensitiveEnvVars)),
			strings.Join(report.AddedSensitiveEnvVars, ", "))
	}
	if len(report.AddedSensitiveEnvVarPrefixes) > 0 {
		verb := "added to sensitive_env_var_prefixes"
		if report.CreatedSensitiveEnvVarPrefixes {
			verb = "created sensitive_env_var_prefixes with"
		}
		fmt.Printf("  - %s %d entr%s: %s\n", verb,
			len(report.AddedSensitiveEnvVarPrefixes), pluralY(len(report.AddedSensitiveEnvVarPrefixes)),
			strings.Join(report.AddedSensitiveEnvVarPrefixes, ", "))
	}
	return nil
}

func pluralY(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

func runTest(args []string) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	testTool := fs.String("test-tool", "Bash", "tool name to test")
	testJSON := fs.Bool("test-json", false, "emit raw JSON envelope")
	fs.Usage = func() {
		_, _ = fmt.Fprintln(fs.Output(), "usage: turnstile --test [--test-tool <tool>] [--test-json] <command>")
	}
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(1)
	}
	command := fs.Arg(0)

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: config error —", err)
		os.Exit(1)
	}

	var toolInput map[string]any
	if *testTool == "Bash" {
		toolInput = map[string]any{"command": command}
	} else {
		toolInput = map[string]any{"input": command}
	}

	decision, reason := gate.New(cfg).Decide(*testTool, toolInput)

	if *testJSON {
		output := hookOutput{
			EventName: "PreToolUse",
			Decision:  decision,
		}
		if decision == "allow" {
			output.AdditionalContext = reason
		} else {
			output.Reason = reason
		}
		env := envelope{Output: output}
		out, _ := json.Marshal(env)
		fmt.Println(string(out))
	} else {
		if reason != "" {
			fmt.Println(reason)
		} else {
			fmt.Println(decision)
		}
	}

	exitCode := map[string]int{
		"allow": 0,
		"ask":   1,
		"deny":  2,
		"defer": 1,
	}
	os.Exit(exitCode[decision])
}

type hookOutput struct {
	EventName         string `json:"hookEventName"`
	Decision          string `json:"permissionDecision"`
	Reason            string `json:"permissionDecisionReason,omitempty"`
	AdditionalContext string `json:"additionalContext,omitempty"`
}

type envelope struct {
	Output hookOutput `json:"hookSpecificOutput"`
}

type hookInput struct {
	ToolName      string         `json:"tool_name"`
	ToolInput     map[string]any `json:"tool_input"`
	HookEventName string         `json:"hook_event_name"`
}

func emit(w io.Writer, decision, reason string) {
	output := hookOutput{
		EventName: "PreToolUse",
		Decision:  decision,
	}
	// allow → additionalContext; defer → no reason field (per PreToolUse spec);
	// ask/deny → permissionDecisionReason.
	switch decision {
	case "allow":
		output.AdditionalContext = reason
	case "defer":
		// no reason field
	default:
		output.Reason = reason
	}
	env := envelope{Output: output}
	out, err := json.Marshal(env)
	if err != nil {
		// On marshal failure, emit a hard-coded literal envelope to keep the gate observable.
		// This is a rare edge case (non-marshalable value), but we must emit something deterministic.
		_, _ = fmt.Fprintln(w, `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"turnstile: marshal error"}}`)
		return
	}
	_, _ = fmt.Fprintln(w, string(out))
}

func runInstall(args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	withSelfService := fs.Bool("with-self-service", false, "append permission-self-service paragraph to ~/.claude/CLAUDE.md")
	fs.Usage = func() {
		_, _ = fmt.Fprintln(fs.Output(), "usage: turnstile install [--with-self-service]")
		_, _ = fmt.Fprintln(fs.Output(), "\nInstalls the turnstile skill and PreToolUse hook configuration.")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("get home dir: %w", err)
	}

	var changes []string

	// 1. Install SKILL.md
	skillPath := filepath.Join(homeDir, ".claude", "skills", "turnstile", "SKILL.md")
	if err := os.MkdirAll(filepath.Dir(skillPath), 0o750); err != nil {
		return fmt.Errorf("create skill directory: %w", err)
	}

	existing, err := os.ReadFile(skillPath) //nolint:gosec // skillPath is built from UserHomeDir, not user input
	if err != nil || string(existing) != skillMD {
		if err := os.WriteFile(skillPath, []byte(skillMD), 0o600); err != nil {
			return fmt.Errorf("write skill file: %w", err)
		}
		changes = append(changes, fmt.Sprintf("wrote %s", skillPath))
	}

	// 2. Update settings.json with PreToolUse hook
	settingsPath := filepath.Join(homeDir, ".claude", "settings.json")
	hookChanged, err := installHook(settingsPath)
	if err != nil {
		return fmt.Errorf("install hook: %w", err)
	}
	if hookChanged {
		changes = append(changes, fmt.Sprintf("added PreToolUse hook entry to %s", settingsPath))
	}

	// 3. Optionally append to CLAUDE.md
	if *withSelfService {
		claudeMDPath := filepath.Join(homeDir, ".claude", "CLAUDE.md")
		selfServiceParagraph := `
## Turnstile Permission Self-Service

When a Bash command fails with a "deny:" or "ask:" message from turnstile, use the /turnstile skill to propose adding it to your allowlist. Example: /turnstile add allow 'terraform\b'.
`
		if err := os.MkdirAll(filepath.Dir(claudeMDPath), 0o750); err != nil {
			return fmt.Errorf("create .claude directory: %w", err)
		}

		existing, err := os.ReadFile(claudeMDPath) //nolint:gosec // claudeMDPath is built from UserHomeDir
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("read CLAUDE.md: %w", err)
		}

		if !containsSubstring(string(existing), "Turnstile Permission Self-Service") {
			f, err := os.OpenFile(claudeMDPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // claudeMDPath is built from UserHomeDir
			if err != nil {
				return fmt.Errorf("open CLAUDE.md: %w", err)
			}
			if _, err := f.WriteString(selfServiceParagraph); err != nil {
				_ = f.Close()
				return fmt.Errorf("write CLAUDE.md: %w", err)
			}
			if err := f.Close(); err != nil {
				return fmt.Errorf("close CLAUDE.md: %w", err)
			}
			changes = append(changes, fmt.Sprintf("appended self-service paragraph to %s", claudeMDPath))
		}
	}

	if len(changes) == 0 {
		fmt.Println("turnstile is already installed (no changes needed)")
	} else {
		fmt.Println("installed turnstile:")
		for _, c := range changes {
			fmt.Printf("  - %s\n", c)
		}
	}
	return nil
}

func runUninstall(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	fs.Usage = func() {
		_, _ = fmt.Fprintln(fs.Output(), "usage: turnstile uninstall")
		_, _ = fmt.Fprintln(fs.Output(), "\nRemoves the turnstile skill and PreToolUse hook configuration.")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("get home dir: %w", err)
	}

	var changes []string

	// 1. Remove SKILL.md
	skillPath := filepath.Join(homeDir, ".claude", "skills", "turnstile", "SKILL.md")
	if _, err := os.Stat(skillPath); err == nil {
		if err := os.Remove(skillPath); err != nil {
			return fmt.Errorf("remove skill file: %w", err)
		}
		changes = append(changes, fmt.Sprintf("removed %s", skillPath))

		// Try to remove empty parent directories
		skillDir := filepath.Dir(skillPath)
		if entries, err := os.ReadDir(skillDir); err == nil && len(entries) == 0 {
			_ = os.Remove(skillDir)
		}
	}

	// 2. Remove PreToolUse hook from settings.json
	settingsPath := filepath.Join(homeDir, ".claude", "settings.json")
	hookRemoved, err := uninstallHook(settingsPath)
	if err != nil {
		return fmt.Errorf("remove hook: %w", err)
	}
	if hookRemoved {
		changes = append(changes, fmt.Sprintf("removed PreToolUse hook entry from %s", settingsPath))
	}

	if len(changes) == 0 {
		fmt.Println("turnstile is not installed (no changes needed)")
	} else {
		fmt.Println("uninstalled turnstile:")
		for _, c := range changes {
			fmt.Printf("  - %s\n", c)
		}
	}
	return nil
}

func installHook(settingsPath string) (bool, error) {
	// Read existing settings, or start with empty object
	var settings map[string]any
	data, err := os.ReadFile(settingsPath) //nolint:gosec // settingsPath is built from UserHomeDir
	if err != nil {
		if !os.IsNotExist(err) {
			return false, fmt.Errorf("read settings: %w", err)
		}
		settings = make(map[string]any)
	} else {
		if err := json.Unmarshal(data, &settings); err != nil {
			return false, fmt.Errorf("parse settings: %w", err)
		}
	}

	// Navigate to hooks.PreToolUse array
	hooks, ok := settings["hooks"].(map[string]any)
	if !ok {
		hooks = make(map[string]any)
		settings["hooks"] = hooks
	}

	preToolUse, ok := hooks["PreToolUse"].([]any)
	if !ok {
		preToolUse = []any{}
	}

	// Check if a hook with command: turnstile already exists
	for _, entry := range preToolUse {
		entryMap, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		hooksArray, ok := entryMap["hooks"].([]any)
		if !ok {
			continue
		}
		for _, h := range hooksArray {
			hookMap, ok := h.(map[string]any)
			if !ok {
				continue
			}
			if cmd, ok := hookMap["command"].(string); ok && cmd == "turnstile" {
				// Already installed
				return false, nil
			}
		}
	}

	// Add the turnstile hook entry
	newEntry := map[string]any{
		"hooks": []any{
			map[string]any{
				"type":    "command",
				"command": "turnstile",
				"timeout": 1,
			},
		},
	}
	preToolUse = append(preToolUse, newEntry)
	hooks["PreToolUse"] = preToolUse

	// Write back atomically
	return true, writeSettingsAtomic(settingsPath, settings)
}

func uninstallHook(settingsPath string) (bool, error) {
	data, err := os.ReadFile(settingsPath) //nolint:gosec // settingsPath is built from UserHomeDir
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("read settings: %w", err)
	}

	var settings map[string]any
	if err := json.Unmarshal(data, &settings); err != nil {
		return false, fmt.Errorf("parse settings: %w", err)
	}

	hooks, ok := settings["hooks"].(map[string]any)
	if !ok {
		return false, nil
	}

	preToolUse, ok := hooks["PreToolUse"].([]any)
	if !ok {
		return false, nil
	}

	// Filter out entries with command: turnstile
	var filtered []any
	removed := false
	for _, entry := range preToolUse {
		entryMap, ok := entry.(map[string]any)
		if !ok {
			filtered = append(filtered, entry)
			continue
		}
		hooksArray, ok := entryMap["hooks"].([]any)
		if !ok {
			filtered = append(filtered, entry)
			continue
		}

		hasTurnstile := false
		for _, h := range hooksArray {
			hookMap, ok := h.(map[string]any)
			if !ok {
				continue
			}
			if cmd, ok := hookMap["command"].(string); ok && cmd == "turnstile" {
				hasTurnstile = true
				break
			}
		}

		if !hasTurnstile {
			filtered = append(filtered, entry)
		} else {
			removed = true
		}
	}

	if !removed {
		return false, nil
	}

	hooks["PreToolUse"] = filtered
	return true, writeSettingsAtomic(settingsPath, settings)
}

func writeSettingsAtomic(settingsPath string, settings map[string]any) error {
	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o750); err != nil {
		return fmt.Errorf("create settings directory: %w", err)
	}

	// Marshal with indentation
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal settings: %w", err)
	}

	// Write to tempfile and rename
	tmpPath := settingsPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return fmt.Errorf("write temp settings: %w", err)
	}

	// Get original file permissions if it exists
	if info, err := os.Stat(settingsPath); err == nil {
		if err := os.Chmod(tmpPath, info.Mode()); err != nil {
			_ = os.Remove(tmpPath)
			return fmt.Errorf("chmod temp settings: %w", err)
		}
	}

	if err := os.Rename(tmpPath, settingsPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename settings: %w", err)
	}

	return nil
}

func containsSubstring(s, substr string) bool {
	// Simple substring check (case-sensitive)
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
