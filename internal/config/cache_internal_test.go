package config

import (
	"encoding/gob"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestCache_SchemaVersionMismatchIsRejected asserts that a cache file written
// by a binary with a different schema version is ignored, forcing a recompile
// from source. Without this guard, a binary upgrade that adds new fields to
// cacheData (e.g. SensitiveEnvVars) would silently zero-fill them on decode
// from an older cache, leaving sensitive-env-var protection disabled until
// the user happened to touch their config.toml.
func TestCache_SchemaVersionMismatchIsRejected(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(configPath, []byte(`allow = ['git\b']
deny = []
tools = ["Read"]
sensitive_env_vars = ['PATH']
sensitive_env_var_prefixes = ['LD_']
`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TURNSTILE_CONFIG", configPath)

	// Write a stale cache: schema version 0 (i.e. an older binary's cache
	// where the field didn't exist) and an empty SensitiveEnvVars list to
	// simulate the "silently zero-filled new field" scenario.
	cachePath := filepath.Join(dir, "config.cache.gob")
	stale := cacheData{
		SchemaVersion:    0,
		AllowPattern:     `^(?:(?:git\b))`,
		ToolsList:        []string{"Read"},
		SensitiveEnvVars: nil,
	}
	f, err := os.Create(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := gob.NewEncoder(f).Encode(&stale); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	// Make the cache mtime newer than the source so the mtime check would
	// otherwise accept it — only the schema-version check should reject it.
	future := time.Now().Add(time.Minute)
	if err := os.Chtimes(cachePath, future, future); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// If the stale cache had been honored, SensitiveEnvVars would be empty.
	// The schema-version reject forces a fresh compile from source, where
	// PATH and LD_ are present.
	if _, ok := cfg.SensitiveEnvVars["PATH"]; !ok {
		t.Error("PATH missing from SensitiveEnvVars — stale cache was honored despite version mismatch")
	}
	found := false
	for _, p := range cfg.SensitiveEnvVarPrefixes {
		if p == "LD_" {
			found = true
			break
		}
	}
	if !found {
		t.Error("LD_ missing from SensitiveEnvVarPrefixes — stale cache was honored despite version mismatch")
	}
}
