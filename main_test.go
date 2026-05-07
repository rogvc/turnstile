package main_test

import (
	"encoding/json"
	"strings"
	"testing"

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
