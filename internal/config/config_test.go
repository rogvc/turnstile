package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rogvc/turnstile/internal/config"
)

func TestCompile(t *testing.T) {
	t.Run("valid allow deny tools", func(t *testing.T) {
		cfg, err := config.Compile(
			[]string{`git\b`, `ls\b`},
			[]string{`sudo\b`},
			[]string{"Read", "Write"},
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !cfg.AllowRE.MatchString("git status") {
			t.Error("allowRE should match 'git status'")
		}
		if cfg.AllowRE.MatchString("unknown cmd") {
			t.Error("allowRE should not match 'unknown cmd'")
		}
		if !cfg.Denies("sudo rm -rf /") {
			t.Error("deny list should match 'sudo rm -rf /'")
		}
		if cfg.Denies("git status") {
			t.Error("deny list should not match 'git status'")
		}
		if _, ok := cfg.Tools["Read"]; !ok {
			t.Error("tools should contain 'Read'")
		}
		if _, ok := cfg.Tools["Write"]; !ok {
			t.Error("tools should contain 'Write'")
		}
	})

	t.Run("empty allow returns error", func(t *testing.T) {
		_, err := config.Compile(nil, nil, nil)
		if err == nil {
			t.Fatal("expected error for empty allow list")
		}
	})

	t.Run("invalid allow regex returns error", func(t *testing.T) {
		_, err := config.Compile([]string{`[invalid`}, nil, nil)
		if err == nil {
			t.Fatal("expected error for invalid allow regex")
		}
	})

	t.Run("invalid deny regex returns error", func(t *testing.T) {
		_, err := config.Compile([]string{`git\b`}, []string{`[invalid`}, nil)
		if err == nil {
			t.Fatal("expected error for invalid deny regex")
		}
	})

	t.Run("empty deny list never matches", func(t *testing.T) {
		cfg, err := config.Compile([]string{`git\b`}, nil, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Denies("sudo rm -rf /") {
			t.Error("empty deny list should not match 'sudo rm -rf /'")
		}
		if cfg.Denies("passwd root") {
			t.Error("empty deny list should not match 'passwd root'")
		}
	})

	t.Run("empty tools map", func(t *testing.T) {
		cfg, err := config.Compile([]string{`git\b`}, nil, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(cfg.Tools) != 0 {
			t.Errorf("expected empty tools map, got %d entries", len(cfg.Tools))
		}
	})

	t.Run("deny pattern with lookaround returns helpful error", func(t *testing.T) {
		_, err := config.Compile([]string{`git\b`}, []string{`(?=foo)sudo`}, nil)
		if err == nil {
			t.Fatal("expected error for deny pattern with lookaround")
		}
		if !strings.Contains(err.Error(), "RE2 does not support lookarounds") {
			t.Errorf("error message should contain 'RE2 does not support lookarounds', got: %v", err)
		}
	})
}

func TestLoad(t *testing.T) {
	t.Run("valid config file", func(t *testing.T) {
		f, err := os.CreateTemp("", "turnstile-*.toml")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(f.Name()) })
		if _, err := f.WriteString("allow = ['git\\b']\ndeny = []\ntools = [\"Read\"]\n"); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}

		t.Setenv("TURNSTILE_CONFIG", f.Name())
		cfg, err := config.Load()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !cfg.AllowRE.MatchString("git status") {
			t.Error("loaded config should allow 'git status'")
		}
	})

	t.Run("invalid TOML returns error", func(t *testing.T) {
		f, err := os.CreateTemp("", "turnstile-*.toml")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(f.Name()) })
		if _, err := f.WriteString(`not valid toml =[[[`); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}

		t.Setenv("TURNSTILE_CONFIG", f.Name())
		_, err = config.Load()
		if err == nil {
			t.Fatal("expected error for invalid TOML")
		}
	})

	t.Run("missing file seeds default and loads successfully", func(t *testing.T) {
		dir, err := os.MkdirTemp("", "turnstile-seed-*")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })

		// Use UserConfigDir override instead of TURNSTILE_CONFIG
		// to test the default seeding path behavior
		t.Setenv("XDG_CONFIG_HOME", dir)

		cfg, err := config.Load()
		if err != nil {
			t.Fatalf("expected seed+load to succeed, got: %v", err)
		}
		if cfg == nil {
			t.Fatal("expected non-nil config after seeding")
		}
		expectedPath := filepath.Join(dir, "turnstile", "config.toml")
		if _, err := os.Stat(expectedPath); err != nil {
			t.Errorf("expected seeded file to exist at %s: %v", expectedPath, err)
		}
	})

	t.Run("seeded file is not overwritten on second load", func(t *testing.T) {
		f, err := os.CreateTemp("", "turnstile-*.toml")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(f.Name()) })
		if _, err := f.WriteString("allow = ['ls\\b']\ndeny = []\ntools = []\n"); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}

		t.Setenv("TURNSTILE_CONFIG", f.Name())
		cfg, err := config.Load()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !cfg.AllowRE.MatchString("ls -la") {
			t.Error("second load should use existing file, not overwrite with defaults")
		}
	})

	t.Run("symlink at config path returns error and does not overwrite target", func(t *testing.T) {
		dir, err := os.MkdirTemp("", "turnstile-symlink-*")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })

		// Create a target file that we will link to
		targetPath := filepath.Join(dir, "target.toml")
		targetContent := []byte("allow = ['echo\\b']\ndeny = []\ntools = []\n")
		if err := os.WriteFile(targetPath, targetContent, 0o600); err != nil {
			t.Fatal(err)
		}

		// Create a symlink at the expected config location
		configDir := filepath.Join(dir, "turnstile")
		if err := os.MkdirAll(configDir, 0o750); err != nil {
			t.Fatal(err)
		}
		linkPath := filepath.Join(configDir, "config.toml")
		if err := os.Symlink(targetPath, linkPath); err != nil {
			t.Fatal(err)
		}

		// Override UserConfigDir to point to our test directory
		// This ensures we test the default location behavior, not TURNSTILE_CONFIG
		t.Setenv("XDG_CONFIG_HOME", dir)

		// Attempt to load, which should detect the symlink during seed and refuse to proceed
		_, err = config.Load()
		if err == nil {
			t.Fatal("expected error when config path is a symlink")
		}

		// Verify the target file was not modified
		content, err := os.ReadFile(targetPath)
		if err != nil {
			t.Fatal(err)
		}
		if string(content) != string(targetContent) {
			t.Error("symlink target was modified; expected it to remain unchanged")
		}
	})

	t.Run("TURNSTILE_CONFIG with directory traversal is rejected", func(t *testing.T) {
		dir, err := os.MkdirTemp("", "turnstile-traversal-*")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })

		// Create a valid config file
		configPath := filepath.Join(dir, "config.toml")
		if err := os.WriteFile(configPath, []byte("allow = ['git\\b']\ndeny = []\ntools = []\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		// Try to reference it with directory traversal
		traversalPath := filepath.Join(dir, "subdir", "..", "config.toml")
		t.Setenv("TURNSTILE_CONFIG", traversalPath)

		// The path should be cleaned and resolve successfully since it points to a valid file we own
		cfg, err := config.Load()
		if err != nil {
			t.Fatalf("expected Load to succeed after cleaning path traversal, got: %v", err)
		}
		if cfg == nil {
			t.Fatal("expected non-nil config")
		}
	})

	t.Run("TURNSTILE_CONFIG missing file returns error without seeding", func(t *testing.T) {
		dir, err := os.MkdirTemp("", "turnstile-missing-*")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })

		missingPath := filepath.Join(dir, "missing.toml")
		t.Setenv("TURNSTILE_CONFIG", missingPath)

		_, err = config.Load()
		if err == nil {
			t.Fatal("expected error when TURNSTILE_CONFIG points to missing file")
		}
		if !strings.Contains(err.Error(), "no such file or directory") && !strings.Contains(err.Error(), "does not exist") {
			t.Errorf("error message should indicate file does not exist, got: %v", err)
		}

		// Verify the file was not created
		if _, err := os.Stat(missingPath); err == nil {
			t.Error("expected file to remain non-existent, but it was created")
		}
	})

	t.Run("default path seeding still works", func(t *testing.T) {
		dir, err := os.MkdirTemp("", "turnstile-default-seed-*")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })

		// Use UserConfigDir override to test default seeding
		t.Setenv("XDG_CONFIG_HOME", dir)

		cfg, err := config.Load()
		if err != nil {
			t.Fatalf("expected default path seeding to succeed, got: %v", err)
		}
		if cfg == nil {
			t.Fatal("expected non-nil config after seeding")
		}

		// Verify the seeded file exists at the expected location
		expectedPath := filepath.Join(dir, "turnstile", "config.toml")
		if _, err := os.Stat(expectedPath); err != nil {
			t.Errorf("expected seeded file at %s, but stat failed: %v", expectedPath, err)
		}
	})

	t.Run("undecoded keys returns error", func(t *testing.T) {
		f, err := os.CreateTemp("", "turnstile-*.toml")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(f.Name()) })
		// Use a typo: tools_default_to_defere instead of tools_default_to_defer
		if _, err := f.WriteString("allow = ['git\\b']\ndeny = []\ntools = [\"Read\"]\ntools_default_to_defere = true\n"); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}

		t.Setenv("TURNSTILE_CONFIG", f.Name())
		_, err = config.Load()
		if err == nil {
			t.Fatal("expected error for config with typo in key")
		}
		if !strings.Contains(err.Error(), "unknown config keys") {
			t.Errorf("error message should contain 'unknown config keys', got: %v", err)
		}
	})

	t.Run("typo in safe_path_exemptions produces error", func(t *testing.T) {
		f, err := os.CreateTemp("", "turnstile-*.toml")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(f.Name()) })
		// Use singular form: safe_path_exemption instead of safe_path_exemptions
		if _, err := f.WriteString("allow = ['git\\b']\ndeny = []\ntools = []\nsafe_path_exemption = []\n"); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}

		t.Setenv("TURNSTILE_CONFIG", f.Name())
		_, err = config.Load()
		if err == nil {
			t.Fatal("expected error for config with typo safe_path_exemption")
		}
		if !strings.Contains(err.Error(), "unknown config keys") {
			t.Errorf("error message should contain 'unknown config keys', got: %v", err)
		}
	})

	t.Run("typo in strip_wrappers produces error", func(t *testing.T) {
		f, err := os.CreateTemp("", "turnstile-*.toml")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(f.Name()) })
		// Use camelCase: stripWrappers instead of strip_wrappers
		if _, err := f.WriteString("allow = ['git\\b']\ndeny = []\ntools = []\nstripWrappers = [\"time\"]\n"); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}

		t.Setenv("TURNSTILE_CONFIG", f.Name())
		_, err = config.Load()
		if err == nil {
			t.Fatal("expected error for config with camelCase stripWrappers")
		}
		if !strings.Contains(err.Error(), "unknown config keys") {
			t.Errorf("error message should contain 'unknown config keys', got: %v", err)
		}
	})

	t.Run("cache hit on second load", func(t *testing.T) {
		dir, err := os.MkdirTemp("", "turnstile-cache-*")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })

		configPath := filepath.Join(dir, "config.toml")
		if err := os.WriteFile(configPath, []byte("allow = ['git\\b']\ndeny = ['sudo\\b']\ntools = [\"Read\"]\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		t.Setenv("TURNSTILE_CONFIG", configPath)

		// First load: cache miss
		cfg1, err := config.Load()
		if err != nil {
			t.Fatalf("first load failed: %v", err)
		}

		// Verify cache file was created (named after the config file)
		cachePath := filepath.Join(dir, "config.cache.gob")
		if _, err := os.Stat(cachePath); err != nil {
			t.Errorf("cache file should exist at %s: %v", cachePath, err)
		}

		// Second load: cache hit
		cfg2, err := config.Load()
		if err != nil {
			t.Fatalf("second load failed: %v", err)
		}

		// Verify configs are functionally equivalent
		if !cfg1.AllowRE.MatchString("git status") || !cfg2.AllowRE.MatchString("git status") {
			t.Error("both configs should match 'git status'")
		}
		if !cfg1.Denies("sudo rm -rf /") || !cfg2.Denies("sudo rm -rf /") {
			t.Error("both configs should deny 'sudo rm -rf /'")
		}
		if _, ok := cfg1.Tools["Read"]; !ok {
			t.Error("first config should contain 'Read' tool")
		}
		if _, ok := cfg2.Tools["Read"]; !ok {
			t.Error("second config should contain 'Read' tool")
		}
	})

	t.Run("cache invalidation on source modification", func(t *testing.T) {
		dir, err := os.MkdirTemp("", "turnstile-cache-invalidation-*")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })

		configPath := filepath.Join(dir, "config.toml")
		if err := os.WriteFile(configPath, []byte("allow = ['git\\b']\ndeny = []\ntools = []\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		t.Setenv("TURNSTILE_CONFIG", configPath)

		// First load: create cache
		cfg1, err := config.Load()
		if err != nil {
			t.Fatalf("first load failed: %v", err)
		}

		// Sleep to ensure file modification time is later than cache creation
		// (some filesystems have low timestamp precision)
		time.Sleep(10 * time.Millisecond)

		// Modify the source config
		if err := os.WriteFile(configPath, []byte("allow = ['ls\\b']\ndeny = []\ntools = []\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		// Second load: cache should be invalidated and reload from source
		cfg2, err := config.Load()
		if err != nil {
			t.Fatalf("second load after modification failed: %v", err)
		}

		// Verify first config matched git
		if !cfg1.AllowRE.MatchString("git status") {
			t.Error("first config should match 'git status'")
		}
		if cfg1.AllowRE.MatchString("ls -la") {
			t.Error("first config should not match 'ls -la'")
		}

		// Verify second config matches ls (from modified source)
		if !cfg2.AllowRE.MatchString("ls -la") {
			t.Error("second config should match 'ls -la' after source modification")
		}
		if cfg2.AllowRE.MatchString("git status") {
			t.Error("second config should not match 'git status' after source modification")
		}
	})
}

func BenchmarkLoad(b *testing.B) {
	dir, err := os.MkdirTemp("", "turnstile-bench-*")
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	// Create a config with multiple patterns to make compilation non-trivial
	configContent := `allow = ['git\b', 'ls\b', 'cd\b', 'pwd\b', 'cat\b', 'grep\b', 'find\b', 'sed\b', 'awk\b', 'echo\b']
deny = ['sudo\b', 'rm -rf', 'dd if=', 'mkfs', 'fdisk', ':(){:|:&};:', 'curl.*sudo']
tools = ["Read", "Write", "Edit", "Bash"]
`
	configPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(configPath, []byte(configContent), 0o600); err != nil {
		b.Fatal(err)
	}

	b.Setenv("TURNSTILE_CONFIG", configPath)

	b.Run("cache miss", func(b *testing.B) {
		cachePath := filepath.Join(dir, "config.cache.gob")
		for i := 0; i < b.N; i++ {
			// Remove cache to force reparse
			_ = os.Remove(cachePath)
			_, err := config.Load()
			if err != nil {
				b.Fatalf("load failed: %v", err)
			}
		}
	})

	b.Run("cache hit", func(b *testing.B) {
		// Prime the cache
		_, err := config.Load()
		if err != nil {
			b.Fatalf("initial load failed: %v", err)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := config.Load()
			if err != nil {
				b.Fatalf("load failed: %v", err)
			}
		}
	})
}
