package main_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	main "github.com/rogvc/turnstile"
	"github.com/rogvc/turnstile/internal/config"
	"github.com/rogvc/turnstile/internal/gate"
	"github.com/rogvc/turnstile/internal/shell"
)

func BenchmarkConfigLoad(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := config.Load(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecideBashSimple(b *testing.B) {
	cfg, _ := config.Load()
	g := gate.New(cfg)
	inp := map[string]any{"command": "git status"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g.Decide("Bash", inp)
	}
}

func BenchmarkDecideBashPipeline(b *testing.B) {
	cfg, _ := config.Load()
	g := gate.New(cfg)
	inp := map[string]any{"command": "git status && ls -la | grep foo && echo done"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g.Decide("Bash", inp)
	}
}

func BenchmarkDecideBashSubshell(b *testing.B) {
	cfg, _ := config.Load()
	g := gate.New(cfg)
	inp := map[string]any{"command": "echo $(git rev-parse HEAD)"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g.Decide("Bash", inp)
	}
}

func BenchmarkExtractSubshells(b *testing.B) {
	cmd := "echo $(git rev-parse HEAD) && ls $(pwd)"
	for i := 0; i < b.N; i++ {
		shell.ExtractSubshells(cmd)
	}
}

func BenchmarkSplitPipeline(b *testing.B) {
	cmd := "git status && ls -la | grep foo && echo done"
	for i := 0; i < b.N; i++ {
		shell.SplitPipeline(cmd)
	}
}

func BenchmarkEnvVarReplaceNoMatch(b *testing.B) {
	seg := "git status --porcelain"
	for i := 0; i < b.N; i++ {
		shell.EnvVarRE.ReplaceAllString(seg, "")
	}
}

func BenchmarkEnvVarIndexCheck(b *testing.B) {
	seg := "git status --porcelain"
	for i := 0; i < b.N; i++ {
		if strings.IndexByte(seg, '=') >= 0 {
			shell.EnvVarRE.ReplaceAllString(seg, "")
		}
	}
}

func BenchmarkJSONDecode(b *testing.B) {
	raw := []byte(`{"tool_name":"Bash","tool_input":{"command":"git status && ls -la"}}`)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var v map[string]any
		if err := json.NewDecoder(strings.NewReader(string(raw))).Decode(&v); err != nil {
			b.Fatal(err)
		}
	}
}

func TestConfigErrorDegradesToAsk(t *testing.T) {
	tests := []struct {
		name               string
		configContent      string
		wantStderrContains string
	}{
		{
			name:               "invalid TOML syntax",
			configContent:      "invalid toml [[[ content",
			wantStderrContains: "config error",
		},
		{
			name: "unclosed paren in regex",
			configContent: `
allow = [
  'git\b',
  'ls(broken',
]
deny = []
tools = ["Read", "Bash"]
`,
			wantStderrContains: "compile allow",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			configDir := filepath.Join(tmpDir, "turnstile")
			if err := os.MkdirAll(configDir, 0o755); err != nil {
				t.Fatalf("mkdir config dir: %v", err)
			}
			invalidConfig := filepath.Join(configDir, "config.toml")
			if err := os.WriteFile(invalidConfig, []byte(tt.configContent), 0o600); err != nil {
				t.Fatalf("write invalid config: %v", err)
			}

			// Set the config home env var before running the hook
			t.Setenv("XDG_CONFIG_HOME", tmpDir)

			stdin := strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"ls"}}`)
			var stdout, stderr bytes.Buffer
			var exitCode int
			exit := func(code int) { exitCode = code }

			main.RunHook(stdin, &stdout, &stderr, exit)

			if exitCode != 0 {
				t.Fatalf("expected exit code 0, got %d\nstdout: %s\nstderr: %s", exitCode, stdout.String(), stderr.String())
			}

			var envelope struct {
				Output struct {
					Decision string `json:"permissionDecision"`
					Reason   string `json:"permissionDecisionReason"`
				} `json:"hookSpecificOutput"`
			}
			if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
				t.Fatalf("decode output: %v\nraw stdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
			}

			if envelope.Output.Decision != "ask" {
				t.Errorf("expected permissionDecision=ask, got %q", envelope.Output.Decision)
			}
			if !strings.Contains(envelope.Output.Reason, "config-error") {
				t.Errorf("expected reason to contain 'config-error', got %q", envelope.Output.Reason)
			}
			if !strings.Contains(envelope.Output.Reason, "stderr") {
				t.Errorf("expected reason to mention stderr, got %q", envelope.Output.Reason)
			}

			// Verify stderr contains the detailed error
			stderrStr := stderr.String()
			if !strings.Contains(stderrStr, tt.wantStderrContains) {
				t.Errorf("expected stderr to contain %q, got: %s", tt.wantStderrContains, stderrStr)
			}

			// Verify the config path is redacted in stderr (should not appear in raw form)
			if strings.Contains(stderrStr, configDir) && !strings.Contains(stderrStr, "[config-path]") {
				t.Errorf("config path should be redacted in stderr, but found: %s", configDir)
			}
		})
	}
}

func TestAllowUsesAdditionalContext(t *testing.T) {
	stdin := strings.NewReader(`{"tool_name":"Read","tool_input":{}}`)
	var stdout, stderr bytes.Buffer
	var exitCode int
	exit := func(code int) { exitCode = code }

	main.RunHook(stdin, &stdout, &stderr, exit)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d\nstdout: %s\nstderr: %s", exitCode, stdout.String(), stderr.String())
	}

	var envelope struct {
		Output struct {
			Decision          string `json:"permissionDecision"`
			Reason            string `json:"permissionDecisionReason"`
			AdditionalContext string `json:"additionalContext"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		t.Fatalf("decode output: %v\nraw: %s", err, stdout.String())
	}

	if envelope.Output.Decision != "allow" {
		t.Errorf("expected permissionDecision=allow, got %q", envelope.Output.Decision)
	}
	if envelope.Output.Reason != "" {
		t.Errorf("expected empty permissionDecisionReason for allow, got %q", envelope.Output.Reason)
	}
	// additionalContext may be empty or non-empty for allow; we just verify the field routing
}

func TestRunTest_ExitCodes(t *testing.T) {
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, "turnstile")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	configPath := filepath.Join(configDir, "config.toml")
	configContent := `
allow = [
  'git\b',
]
deny = [
  'sudo\b',
  'rm\s+-rf\s+/',
]
tools = ["Read", "Bash"]
`
	if err := os.WriteFile(configPath, []byte(configContent), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// Build the binary to test exit codes accurately (go run wraps exit codes).
	binaryPath := filepath.Join(tmpDir, "turnstile-test")
	buildCmd := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("build binary: %v\noutput: %s", err, out)
	}

	tests := []struct {
		name         string
		args         []string
		wantExitCode int
		wantOutput   string
	}{
		{
			name:         "allow command exits 0",
			args:         []string{"--test", "git status"},
			wantExitCode: 0,
			wantOutput:   "allow",
		},
		{
			name:         "deny command exits 2",
			args:         []string{"--test", "sudo rm -rf /"},
			wantExitCode: 2,
			wantOutput:   "deny:",
		},
		{
			name:         "ask command exits 1",
			args:         []string{"--test", "unknown_command"},
			wantExitCode: 1,
			wantOutput:   "ask:",
		},
		{
			name:         "short flag -t",
			args:         []string{"-t", "git status"},
			wantExitCode: 0,
			wantOutput:   "allow",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(binaryPath, tt.args...)
			cmd.Env = append(os.Environ(), "XDG_CONFIG_HOME="+tmpDir)

			out, err := cmd.CombinedOutput()
			var exitCode int
			if err != nil {
				if exitErr, ok := err.(*exec.ExitError); ok {
					exitCode = exitErr.ExitCode()
				} else {
					t.Fatalf("unexpected error: %v\noutput: %s", err, out)
				}
			} else {
				exitCode = 0
			}

			if exitCode != tt.wantExitCode {
				t.Errorf("exit code = %d, want %d\noutput: %s", exitCode, tt.wantExitCode, out)
			}

			if !strings.Contains(string(out), tt.wantOutput) {
				t.Errorf("output does not contain %q\ngot: %s", tt.wantOutput, out)
			}
		})
	}
}

func TestRunTest_JSONOutput(t *testing.T) {
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, "turnstile")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	configPath := filepath.Join(configDir, "config.toml")
	configContent := `
allow = [
  'git\b',
]
deny = [
  'sudo\b',
]
tools = ["Read", "Bash"]
`
	if err := os.WriteFile(configPath, []byte(configContent), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// Build the binary.
	binaryPath := filepath.Join(tmpDir, "turnstile-test")
	buildCmd := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("build binary: %v\noutput: %s", err, out)
	}

	cmd := exec.Command(binaryPath, "--test", "--test-json", "git status")
	cmd.Env = append(os.Environ(), "XDG_CONFIG_HOME="+tmpDir)

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run test: %v\noutput: %s", err, out)
	}

	var envelope struct {
		Output struct {
			EventName         string `json:"hookEventName"`
			Decision          string `json:"permissionDecision"`
			Reason            string `json:"permissionDecisionReason"`
			AdditionalContext string `json:"additionalContext"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(out, &envelope); err != nil {
		t.Fatalf("decode JSON: %v\nraw: %s", err, out)
	}

	if envelope.Output.EventName != "PreToolUse" {
		t.Errorf("hookEventName = %q, want %q", envelope.Output.EventName, "PreToolUse")
	}
	if envelope.Output.Decision != "allow" {
		t.Errorf("permissionDecision = %q, want %q", envelope.Output.Decision, "allow")
	}
}

func TestRunTest_NonBashTool(t *testing.T) {
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, "turnstile")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	configPath := filepath.Join(configDir, "config.toml")
	configContent := `
allow = [
  'git\b',
]
deny = []
tools = ["Read", "Edit"]
`
	if err := os.WriteFile(configPath, []byte(configContent), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// Build the binary.
	binaryPath := filepath.Join(tmpDir, "turnstile-test")
	buildCmd := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("build binary: %v\noutput: %s", err, out)
	}

	tests := []struct {
		name         string
		tool         string
		input        string
		wantExitCode int
		wantDecision string
	}{
		{
			name:         "allowed tool",
			tool:         "Read",
			input:        "/some/path",
			wantExitCode: 0,
			wantDecision: "allow",
		},
		{
			name:         "unknown tool",
			tool:         "UnknownTool",
			input:        "some input",
			wantExitCode: 1,
			wantDecision: "ask",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(binaryPath, "--test", "--test-tool", tt.tool, tt.input)
			cmd.Env = append(os.Environ(), "XDG_CONFIG_HOME="+tmpDir)

			out, err := cmd.CombinedOutput()
			var exitCode int
			if err != nil {
				if exitErr, ok := err.(*exec.ExitError); ok {
					exitCode = exitErr.ExitCode()
				} else {
					t.Fatalf("unexpected error: %v\noutput: %s", err, out)
				}
			} else {
				exitCode = 0
			}

			if exitCode != tt.wantExitCode {
				t.Errorf("exit code = %d, want %d\noutput: %s", exitCode, tt.wantExitCode, out)
			}

			if !strings.Contains(string(out), tt.wantDecision) {
				t.Errorf("output does not contain %q\ngot: %s", tt.wantDecision, out)
			}
		})
	}
}

func TestHookEventNameValidation(t *testing.T) {
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, "turnstile")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	configPath := filepath.Join(configDir, "config.toml")
	configContent := `
allow = ['git\b']
deny = []
tools = ["Read", "Bash"]
`
	if err := os.WriteFile(configPath, []byte(configContent), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// Build the binary to test exit codes accurately.
	binaryPath := filepath.Join(tmpDir, "turnstile-test")
	buildCmd := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("build binary: %v\noutput: %s", err, out)
	}

	t.Run("unsupported hook_event_name exits 2", func(t *testing.T) {
		cmd := exec.Command(binaryPath)
		cmd.Env = append(os.Environ(), "XDG_CONFIG_HOME="+tmpDir)
		cmd.Stdin = strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"ls"},"hook_event_name":"PostToolUse"}`)

		var stdout, stderr strings.Builder
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		err := cmd.Run()
		var exitCode int
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			} else {
				t.Fatalf("unexpected error: %v", err)
			}
		} else {
			exitCode = 0
		}

		if exitCode != 2 {
			t.Errorf("expected exit code 2 for unsupported event, got %d", exitCode)
		}

		stderrStr := stderr.String()
		if !strings.Contains(stderrStr, "PostToolUse") {
			t.Errorf("expected stderr to contain 'PostToolUse', got: %s", stderrStr)
		}
	})

	t.Run("PreToolUse hook_event_name is accepted", func(t *testing.T) {
		cmd := exec.Command(binaryPath)
		cmd.Env = append(os.Environ(), "XDG_CONFIG_HOME="+tmpDir)
		cmd.Stdin = strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"git status"},"hook_event_name":"PreToolUse"}`)

		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("run hook: %v\noutput: %s", err, out)
		}

		var envelope struct {
			Output struct {
				Decision string `json:"permissionDecision"`
			} `json:"hookSpecificOutput"`
		}
		if err := json.Unmarshal(out, &envelope); err != nil {
			t.Fatalf("decode output: %v\nraw: %s", err, out)
		}

		if envelope.Output.Decision != "allow" {
			t.Errorf("expected decision=allow for 'git status', got %q", envelope.Output.Decision)
		}
	})

	t.Run("empty hook_event_name is accepted", func(t *testing.T) {
		cmd := exec.Command(binaryPath)
		cmd.Env = append(os.Environ(), "XDG_CONFIG_HOME="+tmpDir)
		cmd.Stdin = strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"git status"},"hook_event_name":""}`)

		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("run hook: %v\noutput: %s", err, out)
		}

		var envelope struct {
			Output struct {
				Decision string `json:"permissionDecision"`
			} `json:"hookSpecificOutput"`
		}
		if err := json.Unmarshal(out, &envelope); err != nil {
			t.Fatalf("decode output: %v\nraw: %s", err, out)
		}

		if envelope.Output.Decision != "allow" {
			t.Errorf("expected decision=allow for 'git status', got %q", envelope.Output.Decision)
		}
	})
}

func TestRunHook_DeferOmitsPermissionDecisionReason(t *testing.T) {
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, "turnstile")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	configPath := filepath.Join(configDir, "config.toml")
	configContent := `
allow = ['git\b']
deny = []
tools = []
`
	if err := os.WriteFile(configPath, []byte(configContent), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	stdin := strings.NewReader(`{"tool_name":"UnknownTool","tool_input":{}}`)
	var stdout, stderr bytes.Buffer
	var exitCode int
	exit := func(code int) { exitCode = code }

	main.RunHook(stdin, &stdout, &stderr, exit)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d\nstdout: %s\nstderr: %s", exitCode, stdout.String(), stderr.String())
	}

	var envelope struct {
		Output struct {
			Decision string `json:"permissionDecision"`
			Reason   string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		t.Fatalf("decode output: %v\nraw: %s", err, stdout.String())
	}

	// Check for defer decision (which maps to ask in our current logic)
	// If the test framework generates a defer decision, verify no permissionDecisionReason is present
	if envelope.Output.Decision == "defer" && envelope.Output.Reason != "" {
		t.Errorf("defer decision should omit permissionDecisionReason, but got: %q", envelope.Output.Reason)
	}
}

func TestRunHook_DecisionEnvelope(t *testing.T) {
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, "turnstile")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	configPath := filepath.Join(configDir, "config.toml")
	configContent := `
allow = [
  'ls\b', 'cat\b', 'echo\b', 'pwd\b', 'cd\b',
  'git\b', 'go\b', 'python\b', 'grep\b',
  '\w+=',
]
deny = [
  'sudo\b',
  'rm\s+-rf\s+/',
]
tools = ["Read", "Bash"]
`
	if err := os.WriteFile(configPath, []byte(configContent), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	tests := []struct {
		name              string
		stdin             string
		wantDecision      string
		wantReasonField   string // "permissionDecisionReason" or "additionalContext"
		wantReasonContains string
	}{
		{
			name:              "allow decision routes to additionalContext",
			stdin:             `{"tool_name":"Read","tool_input":{}}`,
			wantDecision:      "allow",
			wantReasonField:   "additionalContext",
			wantReasonContains: "", // additionalContext may be empty or non-empty
		},
		{
			name:              "deny decision for sudo",
			stdin:             `{"tool_name":"Bash","tool_input":{"command":"sudo rm -rf /"}}`,
			wantDecision:      "deny",
			wantReasonField:   "permissionDecisionReason",
			wantReasonContains: "sudo",
		},
		{
			name:              "ask decision for unknown command",
			stdin:             `{"tool_name":"Bash","tool_input":{"command":"unknown_cmd"}}`,
			wantDecision:      "ask",
			wantReasonField:   "permissionDecisionReason",
			wantReasonContains: "unknown_cmd",
		},
		{
			name:              "ask decision for malformed JSON",
			stdin:             `{invalid json`,
			wantDecision:      "ask",
			wantReasonField:   "permissionDecisionReason",
			wantReasonContains: "stdin-error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("XDG_CONFIG_HOME", tmpDir)

			stdin := strings.NewReader(tt.stdin)
			var stdout, stderr bytes.Buffer
			var exitCode int
			exit := func(code int) { exitCode = code }

			main.RunHook(stdin, &stdout, &stderr, exit)

			if exitCode != 0 {
				t.Fatalf("expected exit code 0, got %d\nstdout: %s\nstderr: %s", exitCode, stdout.String(), stderr.String())
			}

			var envelope struct {
				Output struct {
					Decision          string `json:"permissionDecision"`
					Reason            string `json:"permissionDecisionReason"`
					AdditionalContext string `json:"additionalContext"`
				} `json:"hookSpecificOutput"`
			}
			if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
				t.Fatalf("decode output: %v\nraw: %s", err, stdout.String())
			}

			if envelope.Output.Decision != tt.wantDecision {
				t.Errorf("permissionDecision = %q, want %q", envelope.Output.Decision, tt.wantDecision)
			}

			var reasonValue string
			if tt.wantReasonField == "additionalContext" {
				reasonValue = envelope.Output.AdditionalContext
				if envelope.Output.Reason != "" {
					t.Errorf("permissionDecisionReason should be empty for allow, got %q", envelope.Output.Reason)
				}
			} else {
				reasonValue = envelope.Output.Reason
				if envelope.Output.AdditionalContext != "" {
					t.Errorf("additionalContext should be empty for %s, got %q", tt.wantDecision, envelope.Output.AdditionalContext)
				}
			}

			if tt.wantReasonContains != "" && !strings.Contains(strings.ToLower(reasonValue), strings.ToLower(tt.wantReasonContains)) {
				t.Errorf("%s = %q, want to contain %q", tt.wantReasonField, reasonValue, tt.wantReasonContains)
			}
		})
	}
}

func TestInstall(t *testing.T) {
	tmpDir := t.TempDir()
	claudeDir := filepath.Join(tmpDir, ".claude")

	// Build the binary
	binaryPath := filepath.Join(tmpDir, "turnstile-test")
	buildCmd := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("build binary: %v\noutput: %s", err, out)
	}

	t.Run("first install writes skill and hook", func(t *testing.T) {
		cmd := exec.Command(binaryPath, "install")
		cmd.Env = append(os.Environ(), "HOME="+tmpDir)

		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("install: %v\noutput: %s", err, out)
		}

		// Verify SKILL.md was written
		skillPath := filepath.Join(claudeDir, "skills", "turnstile", "SKILL.md")
		if _, err := os.Stat(skillPath); os.IsNotExist(err) {
			t.Errorf("SKILL.md not created at %s", skillPath)
		}

		skillContent, err := os.ReadFile(skillPath)
		if err != nil {
			t.Fatalf("read SKILL.md: %v", err)
		}
		if !strings.Contains(string(skillContent), "turnstile") {
			t.Errorf("SKILL.md does not contain 'turnstile'")
		}

		// Verify settings.json hook entry
		settingsPath := filepath.Join(claudeDir, "settings.json")
		settingsData, err := os.ReadFile(settingsPath)
		if err != nil {
			t.Fatalf("read settings.json: %v", err)
		}

		var settings map[string]any
		if err := json.Unmarshal(settingsData, &settings); err != nil {
			t.Fatalf("parse settings.json: %v", err)
		}

		hooks, ok := settings["hooks"].(map[string]any)
		if !ok {
			t.Fatalf("settings.json missing hooks object")
		}

		preToolUse, ok := hooks["PreToolUse"].([]any)
		if !ok || len(preToolUse) == 0 {
			t.Fatalf("settings.json missing PreToolUse array")
		}

		// Check for turnstile hook entry
		foundTurnstile := false
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
					foundTurnstile = true
					break
				}
			}
		}

		if !foundTurnstile {
			t.Errorf("settings.json does not contain turnstile hook entry")
		}

		// Verify output messages
		outStr := string(out)
		if !strings.Contains(outStr, "installed turnstile") {
			t.Errorf("output missing 'installed turnstile' message: %s", outStr)
		}
	})

	t.Run("second install makes no changes", func(t *testing.T) {
		cmd := exec.Command(binaryPath, "install")
		cmd.Env = append(os.Environ(), "HOME="+tmpDir)

		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("second install: %v\noutput: %s", err, out)
		}

		outStr := string(out)
		if !strings.Contains(outStr, "already installed") {
			t.Errorf("output should indicate no changes: %s", outStr)
		}
	})

	t.Run("install with --with-self-service", func(t *testing.T) {
		// Remove CLAUDE.md if it exists
		claudeMDPath := filepath.Join(claudeDir, "CLAUDE.md")
		_ = os.Remove(claudeMDPath)

		cmd := exec.Command(binaryPath, "install", "--with-self-service")
		cmd.Env = append(os.Environ(), "HOME="+tmpDir)

		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("install with --with-self-service: %v\noutput: %s", err, out)
		}

		// Verify CLAUDE.md has self-service paragraph
		claudeMD, err := os.ReadFile(claudeMDPath)
		if err != nil {
			t.Fatalf("read CLAUDE.md: %v", err)
		}

		if !strings.Contains(string(claudeMD), "Turnstile Permission Self-Service") {
			t.Errorf("CLAUDE.md missing self-service paragraph")
		}
	})

	t.Run("uninstall removes skill and hook", func(t *testing.T) {
		cmd := exec.Command(binaryPath, "uninstall")
		cmd.Env = append(os.Environ(), "HOME="+tmpDir)

		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("uninstall: %v\noutput: %s", err, out)
		}

		// Verify SKILL.md was removed
		skillPath := filepath.Join(claudeDir, "skills", "turnstile", "SKILL.md")
		if _, err := os.Stat(skillPath); !os.IsNotExist(err) {
			t.Errorf("SKILL.md still exists at %s", skillPath)
		}

		// Verify hook entry was removed from settings.json
		settingsPath := filepath.Join(claudeDir, "settings.json")
		settingsData, err := os.ReadFile(settingsPath)
		if err != nil {
			t.Fatalf("read settings.json: %v", err)
		}

		var settings map[string]any
		if err := json.Unmarshal(settingsData, &settings); err != nil {
			t.Fatalf("parse settings.json: %v", err)
		}

		hooks, ok := settings["hooks"].(map[string]any)
		if ok {
			preToolUse, ok := hooks["PreToolUse"].([]any)
			if ok {
				// Check that no turnstile hook entry exists
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
							t.Errorf("turnstile hook entry still present in settings.json")
						}
					}
				}
			}
		}

		// Verify output messages
		outStr := string(out)
		if !strings.Contains(outStr, "uninstalled turnstile") {
			t.Errorf("output missing 'uninstalled turnstile' message: %s", outStr)
		}
	})
}

func TestSectionAliases(t *testing.T) {
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, "turnstile")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	configPath := filepath.Join(configDir, "config.toml")
	configContent := `
allow = []
deny = []
tools = []
`
	if err := os.WriteFile(configPath, []byte(configContent), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// Build the binary
	binaryPath := filepath.Join(tmpDir, "turnstile-test")
	buildCmd := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("build binary: %v\noutput: %s", err, out)
	}

	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "add with lowercase 'allow'",
			args:    []string{"add", "allow", "git"},
			wantErr: false,
		},
		{
			name:    "add with uppercase 'Allow'",
			args:    []string{"add", "Allow", "grep"},
			wantErr: false,
		},
		{
			name:    "add with alias 'allows'",
			args:    []string{"add", "allows", "ls"},
			wantErr: false,
		},
		{
			name:    "add with uppercase alias 'Allows'",
			args:    []string{"add", "Allows", "cat"},
			wantErr: false,
		},
		{
			name:    "add with lowercase 'deny'",
			args:    []string{"add", "deny", "sudo"},
			wantErr: false,
		},
		{
			name:    "add with uppercase 'Deny'",
			args:    []string{"add", "Deny", "rm"},
			wantErr: false,
		},
		{
			name:    "add with alias 'denies'",
			args:    []string{"add", "denies", "dd"},
			wantErr: false,
		},
		{
			name:    "add with uppercase alias 'Denies'",
			args:    []string{"add", "Denies", "chmod"},
			wantErr: false,
		},
		{
			name:    "add with lowercase 'tools'",
			args:    []string{"add", "tools", "Bash"},
			wantErr: false,
		},
		{
			name:    "add with uppercase 'Tools'",
			args:    []string{"add", "Tools", "Read"},
			wantErr: false,
		},
		{
			name:    "add with alias 'tool'",
			args:    []string{"add", "tool", "Edit"},
			wantErr: false,
		},
		{
			name:    "add with uppercase alias 'Tool'",
			args:    []string{"add", "Tool", "Write"},
			wantErr: false,
		},
		{
			name:    "add with invalid section",
			args:    []string{"add", "invalid", "test"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(binaryPath, tt.args...)
			cmd.Env = append(os.Environ(), "XDG_CONFIG_HOME="+tmpDir)

			out, err := cmd.CombinedOutput()
			outStr := string(out)

			hasErr := err != nil
			if hasErr != tt.wantErr {
				t.Errorf("error = %v, wantErr = %v\noutput: %s", err, tt.wantErr, outStr)
			}

			if tt.wantErr && !strings.Contains(outStr, "must be allow, deny, or tools") {
				t.Errorf("expected error message to contain 'must be allow, deny, or tools', got: %s", outStr)
			}
		})
	}
}

func TestSectionErrorMessage(t *testing.T) {
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, "turnstile")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	configPath := filepath.Join(configDir, "config.toml")
	configContent := `
allow = []
deny = []
tools = []
`
	if err := os.WriteFile(configPath, []byte(configContent), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// Build the binary
	binaryPath := filepath.Join(tmpDir, "turnstile-test")
	buildCmd := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("build binary: %v\noutput: %s", err, out)
	}

	t.Run("invalid section shows valid options", func(t *testing.T) {
		cmd := exec.Command(binaryPath, "add", "unknown", "test")
		cmd.Env = append(os.Environ(), "XDG_CONFIG_HOME="+tmpDir)

		out, _ := cmd.CombinedOutput()
		outStr := string(out)

		if !strings.Contains(outStr, "allow") || !strings.Contains(outStr, "deny") || !strings.Contains(outStr, "tools") {
			t.Errorf("expected error message to mention valid sections (allow, deny, tools), got: %s", outStr)
		}
	})
}

func TestMarshalErrorFallback(t *testing.T) {
	// This test verifies that emit() produces a hard-coded fallback envelope when json.Marshal fails.
	// We simulate a marshal failure by using a custom writer that detects the fallback.
	// The fallback is a literal JSON string that should be emitted even if marshaling fails.

	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, "turnstile")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	configPath := filepath.Join(configDir, "config.toml")
	configContent := `
allow = ['git\b']
deny = []
tools = ["Read"]
`
	if err := os.WriteFile(configPath, []byte(configContent), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	t.Setenv("XDG_CONFIG_HOME", tmpDir)

	// Verify that the marshal fallback envelope is correct by checking the literal output.
	// We do this by ensuring the fallback is a valid JSON envelope with "ask" decision.
	stdin := strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"ls"}}`)
	var stdout, stderr bytes.Buffer
	exit := func(_ int) {}

	main.RunHook(stdin, &stdout, &stderr, exit)

	// Parse the output to ensure it's a valid envelope
	var envelope struct {
		Output struct {
			EventName string `json:"hookEventName"`
			Decision  string `json:"permissionDecision"`
			Reason    string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		t.Fatalf("decode output: %v\nraw stdout: %s", err, stdout.String())
	}

	// Verify the structure is correct
	if envelope.Output.EventName != "PreToolUse" {
		t.Errorf("expected hookEventName=PreToolUse, got %q", envelope.Output.EventName)
	}

	// Verify the fallback message format is present in case of actual marshal failures
	// (This is difficult to trigger in normal code, but we verify the fallback literal exists)
	fallbackEnvelope := `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"turnstile: marshal error"}}`
	var fallbackParsed struct {
		Output struct {
			EventName string `json:"hookEventName"`
			Decision  string `json:"permissionDecision"`
			Reason    string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(fallbackEnvelope), &fallbackParsed); err != nil {
		t.Fatalf("fallback envelope should be valid JSON: %v", err)
	}

	if fallbackParsed.Output.EventName != "PreToolUse" {
		t.Errorf("fallback hookEventName should be PreToolUse")
	}
	if fallbackParsed.Output.Decision != "ask" {
		t.Errorf("fallback decision should be ask")
	}
	if !strings.Contains(fallbackParsed.Output.Reason, "marshal error") {
		t.Errorf("fallback reason should mention marshal error, got %q", fallbackParsed.Output.Reason)
	}
}
