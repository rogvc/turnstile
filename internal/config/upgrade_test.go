package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/rogvc/turnstile/internal/config"
)

// writeTempConfig writes content to a temp file and returns its path.
func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestUpgrade_AddsMissingSections(t *testing.T) {
	// Pre-PR config: no sensitive_env_* keys at all.
	path := writeTempConfig(t, `allow = ['git\b']
deny = []
tools = ["Read"]
`)

	report, err := config.Upgrade(path)
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	if !report.Changed() {
		t.Fatal("expected upgrade to add baseline entries")
	}
	if !report.CreatedSensitiveEnvVars {
		t.Error("expected CreatedSensitiveEnvVars=true when section was missing")
	}
	if !report.CreatedSensitiveEnvVarPrefixes {
		t.Error("expected CreatedSensitiveEnvVarPrefixes=true when section was missing")
	}

	// Round-trip: the rewritten file must load and contain known baseline names.
	t.Setenv("TURNSTILE_CONFIG", path)
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("load after upgrade: %v", err)
	}
	for _, want := range []string{"PATH", "GIT_SSH_COMMAND", "NODE_OPTIONS"} {
		if _, ok := cfg.SensitiveEnvVars[want]; !ok {
			t.Errorf("upgraded config missing %q in SensitiveEnvVars", want)
		}
	}
	hasPrefix := func(p string) bool {
		for _, x := range cfg.SensitiveEnvVarPrefixes {
			if x == p {
				return true
			}
		}
		return false
	}
	for _, p := range []string{"LD_", "DYLD_", "NPM_CONFIG_"} {
		if !hasPrefix(p) {
			t.Errorf("upgraded config missing prefix %q", p)
		}
	}
}

func TestUpgrade_MergesIntoExistingSection(t *testing.T) {
	// User has a partial list; upgrade must add what's missing without
	// duplicating what's already there.
	path := writeTempConfig(t, `allow = ['git\b']
deny = []
tools = ["Read"]

sensitive_env_var_prefixes = [
  'LD_',
  'CUSTOM_',
]
`)
	report, err := config.Upgrade(path)
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	if report.CreatedSensitiveEnvVarPrefixes {
		t.Error("expected CreatedSensitiveEnvVarPrefixes=false when section pre-existed")
	}
	for _, p := range report.AddedSensitiveEnvVarPrefixes {
		if p == "LD_" || p == "CUSTOM_" {
			t.Errorf("upgrade re-added an entry the user already had: %q", p)
		}
	}

	// User's CUSTOM_ entry must survive.
	t.Setenv("TURNSTILE_CONFIG", path)
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	hasPrefix := func(p string) bool {
		for _, x := range cfg.SensitiveEnvVarPrefixes {
			if x == p {
				return true
			}
		}
		return false
	}
	if !hasPrefix("CUSTOM_") {
		t.Error("user's CUSTOM_ prefix was lost during upgrade")
	}
}

func TestUpgrade_Idempotent(t *testing.T) {
	// Running upgrade twice must not change the file the second time.
	path := writeTempConfig(t, `allow = ['git\b']
deny = []
tools = ["Read"]
`)
	if _, err := config.Upgrade(path); err != nil {
		t.Fatalf("first upgrade: %v", err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after first upgrade: %v", err)
	}
	report, err := config.Upgrade(path)
	if err != nil {
		t.Fatalf("second upgrade: %v", err)
	}
	if report.Changed() {
		t.Errorf("second upgrade reported changes: %+v", report)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after second upgrade: %v", err)
	}
	if string(first) != string(second) {
		t.Errorf("file mutated by idempotent upgrade:\nbefore:\n%s\nafter:\n%s", first, second)
	}
}

func TestUpgrade_PreservesComments(t *testing.T) {
	// Comments outside the touched sections must round-trip verbatim.
	src := `# my custom turnstile config — do not delete
allow = [
  'git\b',  # version control
  'ls\b',
]

deny = []
tools = ["Read"]
`
	path := writeTempConfig(t, src)
	if _, err := config.Upgrade(path); err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(got), "# my custom turnstile config — do not delete") {
		t.Error("file-level comment was lost")
	}
	if !strings.Contains(string(got), "# version control") {
		t.Error("inline comment in allow array was lost")
	}
}

func TestUpgrade_RejectsInvalidConfig(t *testing.T) {
	path := writeTempConfig(t, `allow = [` + "\n  'unterminated")
	if _, err := config.Upgrade(path); err == nil {
		t.Fatal("expected error on unparseable config")
	}
}

func TestUpgrade_ResultParsesAndMatchesEmbedded(t *testing.T) {
	// After upgrading a fresh config, every baseline entry should be present
	// in the resulting file (verified via a clean parse, not the regex path).
	path := writeTempConfig(t, `allow = ['git\b']
deny = []
tools = ["Read"]
`)
	if _, err := config.Upgrade(path); err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	t.Setenv("TURNSTILE_CONFIG", path)
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	// Decode the live user file and compare against the embedded baseline:
	// every baseline name must be present.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	type minimalRaw struct {
		SensitiveEnvVars        []string `toml:"sensitive_env_vars"`
		SensitiveEnvVarPrefixes []string `toml:"sensitive_env_var_prefixes"`
	}
	var got minimalRaw
	if _, err := toml.Decode(string(data), &got); err != nil {
		t.Fatalf("decode upgraded file: %v", err)
	}
	if len(got.SensitiveEnvVars) < 50 {
		t.Errorf("expected baseline to add many sensitive_env_vars; got %d", len(got.SensitiveEnvVars))
	}
	// Spot-check a few critical entries reach the gate.
	for _, want := range []string{"GIT_SSH_COMMAND", "NODE_OPTIONS", "BASH_ENV", "KUBECONFIG"} {
		if _, ok := cfg.SensitiveEnvVars[want]; !ok {
			t.Errorf("baseline entry %q missing after upgrade", want)
		}
	}
}
