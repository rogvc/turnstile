package config_test

import (
	"os"
	"path/filepath"
	"testing"

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

		target := filepath.Join(dir, "sub", "config.toml")
		t.Setenv("TURNSTILE_CONFIG", target)

		cfg, err := config.Load()
		if err != nil {
			t.Fatalf("expected seed+load to succeed, got: %v", err)
		}
		if cfg == nil {
			t.Fatal("expected non-nil config after seeding")
		}
		if _, err := os.Stat(target); err != nil {
			t.Errorf("expected seeded file to exist at %s: %v", target, err)
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
}
