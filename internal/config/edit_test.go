package config_test

import (
	"os"
	"strings"
	"testing"

	"github.com/rogvc/turnstile/internal/config"
)

const multiLineConf = `# Top comment
allow = [
  # Group comment
  'git\b',
  'ls\b',
]

deny = [
  'sudo\b',
]

tools = [
  "Read",
  "Write",
]
`

const singleLineConf = `allow = ['git\b']
deny = []
tools = ["Read", "Write"]
`

func writeTmp(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp("", "turnstile-edit-*.toml")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(f.Name()) })
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return f.Name()
}

func TestAddEntry(t *testing.T) {
	t.Run("add to multi-line allow", func(t *testing.T) {
		path := writeTmp(t, multiLineConf)
		added, err := config.AddEntry(path, "allow", `terraform\b`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !added {
			t.Fatal("expected added=true")
		}
		data, _ := os.ReadFile(path)
		text := string(data)
		if !strings.Contains(text, `'terraform\b'`) {
			t.Error("new entry not found in allow")
		}
		if !strings.Contains(text, `'git\b'`) {
			t.Error("existing entry 'git\\b' was lost")
		}
	})

	t.Run("add to multi-line deny", func(t *testing.T) {
		path := writeTmp(t, multiLineConf)
		added, err := config.AddEntry(path, "deny", `rm\s+-rf\b`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !added {
			t.Fatal("expected added=true")
		}
		data, _ := os.ReadFile(path)
		if !strings.Contains(string(data), `'rm\s+-rf\b'`) {
			t.Error("new deny entry not found")
		}
	})

	t.Run("add to multi-line tools", func(t *testing.T) {
		path := writeTmp(t, multiLineConf)
		added, err := config.AddEntry(path, "tools", "NotebookEdit")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !added {
			t.Fatal("expected added=true")
		}
		data, _ := os.ReadFile(path)
		if !strings.Contains(string(data), `"NotebookEdit"`) {
			t.Error("new tool not found")
		}
	})

	t.Run("add to single-line empty deny", func(t *testing.T) {
		path := writeTmp(t, singleLineConf)
		added, err := config.AddEntry(path, "deny", `passwd\b`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !added {
			t.Fatal("expected added=true")
		}
		data, _ := os.ReadFile(path)
		if !strings.Contains(string(data), `'passwd\b'`) {
			t.Error("new deny entry not found")
		}
	})

	t.Run("add to single-line non-empty tools", func(t *testing.T) {
		path := writeTmp(t, singleLineConf)
		added, err := config.AddEntry(path, "tools", "Edit")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !added {
			t.Fatal("expected added=true")
		}
		data, _ := os.ReadFile(path)
		text := string(data)
		if !strings.Contains(text, `"Edit"`) {
			t.Error("new tool not found")
		}
		if !strings.Contains(text, `"Read"`) || !strings.Contains(text, `"Write"`) {
			t.Error("existing tools were lost")
		}
	})

	t.Run("duplicate returns false, file unchanged", func(t *testing.T) {
		path := writeTmp(t, multiLineConf)
		before, _ := os.ReadFile(path)
		added, err := config.AddEntry(path, "allow", `git\b`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if added {
			t.Fatal("expected added=false for duplicate")
		}
		after, _ := os.ReadFile(path)
		if string(before) != string(after) {
			t.Error("file was modified for a duplicate entry")
		}
	})

	t.Run("invalid regex returns error", func(t *testing.T) {
		path := writeTmp(t, multiLineConf)
		_, err := config.AddEntry(path, "allow", `[invalid`)
		if err == nil {
			t.Fatal("expected error for invalid regex")
		}
	})

	t.Run("invalid section returns error", func(t *testing.T) {
		path := writeTmp(t, multiLineConf)
		_, err := config.AddEntry(path, "badSection", "foo")
		if err == nil {
			t.Fatal("expected error for invalid section")
		}
	})

	t.Run("comments preserved after add", func(t *testing.T) {
		path := writeTmp(t, multiLineConf)
		_, err := config.AddEntry(path, "allow", `cargo\b`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		data, _ := os.ReadFile(path)
		text := string(data)
		if !strings.Contains(text, "# Top comment") {
			t.Error("top comment was lost")
		}
		if !strings.Contains(text, "# Group comment") {
			t.Error("inline group comment was lost")
		}
	})

	t.Run("tools regex validation skipped", func(t *testing.T) {
		path := writeTmp(t, multiLineConf)
		// Tool names are not regexes; this should succeed even if it looks like bad regex
		added, err := config.AddEntry(path, "tools", "mcp__playwright__browser_snapshot")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !added {
			t.Fatal("expected added=true")
		}
	})

	t.Run("malformed toml returns error", func(t *testing.T) {
		path := writeTmp(t, "allow = [")
		_, err := config.AddEntry(path, "allow", "git\\b")
		if err == nil {
			t.Fatal("expected error on malformed TOML")
		}
	})

	t.Run("quoted bracket inside entry preserved", func(t *testing.T) {
		path := writeTmp(t, "allow = ['foo\\\\]bar']\n")
		_, err := config.AddEntry(path, "allow", "newentry")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := os.ReadFile(path)
		if !strings.Contains(string(body), `'foo\\]bar'`) {
			t.Fatalf("original entry truncated: %s", body)
		}
	})

	t.Run("reject single quote in allow value", func(t *testing.T) {
		path := writeTmp(t, multiLineConf)
		_, err := config.AddEntry(path, "allow", "foo'bar")
		if err == nil {
			t.Fatal("expected error for single quote in allow value")
		}
		if !strings.Contains(err.Error(), "'") {
			t.Errorf("error should mention single quote, got: %v", err)
		}
	})

	t.Run("reject double quote in tools value", func(t *testing.T) {
		path := writeTmp(t, multiLineConf)
		_, err := config.AddEntry(path, "tools", `Read"x`)
		if err == nil {
			t.Fatal("expected error for double quote in tools value")
		}
		if !strings.Contains(err.Error(), `"`) {
			t.Errorf("error should mention double quote, got: %v", err)
		}
	})

	t.Run("reject newline in deny value", func(t *testing.T) {
		path := writeTmp(t, multiLineConf)
		_, err := config.AddEntry(path, "deny", "foo\nbar")
		if err == nil {
			t.Fatal("expected error for newline in deny value")
		}
		if !strings.Contains(err.Error(), "newline") && !strings.Contains(err.Error(), "forbidden") {
			t.Errorf("error should mention newline or forbidden character, got: %v", err)
		}
	})

	t.Run("reject closing bracket in value", func(t *testing.T) {
		path := writeTmp(t, multiLineConf)
		_, err := config.AddEntry(path, "allow", "foo]bar")
		if err == nil {
			t.Fatal("expected error for ] in value")
		}
		if !strings.Contains(err.Error(), "]") {
			t.Errorf("error should mention ], got: %v", err)
		}
	})

	t.Run("reject carriage return in value", func(t *testing.T) {
		path := writeTmp(t, multiLineConf)
		_, err := config.AddEntry(path, "allow", "foo\rbar")
		if err == nil {
			t.Fatal("expected error for carriage return in value")
		}
	})
}

func TestRemoveEntry(t *testing.T) {
	t.Run("remove from multi-line allow", func(t *testing.T) {
		path := writeTmp(t, multiLineConf)
		removed, err := config.RemoveEntry(path, "allow", `ls\b`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !removed {
			t.Fatal("expected removed=true")
		}
		data, _ := os.ReadFile(path)
		text := string(data)
		if strings.Contains(text, `'ls\b'`) {
			t.Error("entry 'ls\\b' was not removed")
		}
		if !strings.Contains(text, `'git\b'`) {
			t.Error("other entry 'git\\b' was lost")
		}
	})

	t.Run("remove from multi-line deny", func(t *testing.T) {
		path := writeTmp(t, multiLineConf)
		removed, err := config.RemoveEntry(path, "deny", `sudo\b`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !removed {
			t.Fatal("expected removed=true")
		}
		data, _ := os.ReadFile(path)
		if strings.Contains(string(data), `'sudo\b'`) {
			t.Error("entry 'sudo\\b' was not removed from deny")
		}
	})

	t.Run("remove from multi-line tools", func(t *testing.T) {
		path := writeTmp(t, multiLineConf)
		removed, err := config.RemoveEntry(path, "tools", "Write")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !removed {
			t.Fatal("expected removed=true")
		}
		data, _ := os.ReadFile(path)
		text := string(data)
		if strings.Contains(text, `"Write"`) {
			t.Error("\"Write\" was not removed from tools")
		}
		if !strings.Contains(text, `"Read"`) {
			t.Error("other tool \"Read\" was lost")
		}
	})

	t.Run("remove from single-line tools", func(t *testing.T) {
		path := writeTmp(t, singleLineConf)
		removed, err := config.RemoveEntry(path, "tools", "Read")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !removed {
			t.Fatal("expected removed=true")
		}
		data, _ := os.ReadFile(path)
		text := string(data)
		if strings.Contains(text, `"Read"`) {
			t.Error("\"Read\" was not removed")
		}
		if !strings.Contains(text, `"Write"`) {
			t.Error("other tool \"Write\" was lost")
		}
	})

	t.Run("not found returns false, file unchanged", func(t *testing.T) {
		path := writeTmp(t, multiLineConf)
		before, _ := os.ReadFile(path)
		removed, err := config.RemoveEntry(path, "allow", `unknown\b`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if removed {
			t.Fatal("expected removed=false")
		}
		after, _ := os.ReadFile(path)
		if string(before) != string(after) {
			t.Error("file was modified for a not-found removal")
		}
	})

	t.Run("invalid section returns error", func(t *testing.T) {
		path := writeTmp(t, multiLineConf)
		_, err := config.RemoveEntry(path, "badSection", "foo")
		if err == nil {
			t.Fatal("expected error for invalid section")
		}
	})

	t.Run("comments preserved after remove", func(t *testing.T) {
		path := writeTmp(t, multiLineConf)
		_, err := config.RemoveEntry(path, "allow", `ls\b`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		data, _ := os.ReadFile(path)
		text := string(data)
		if !strings.Contains(text, "# Top comment") {
			t.Error("top comment was lost")
		}
		if !strings.Contains(text, "# Group comment") {
			t.Error("group comment was lost")
		}
	})
}

func TestCanonicalize(t *testing.T) {
	tests := []struct {
		section string
		value   string
		want    string
	}{
		{"allow", "rm", `\brm\b`},
		{"deny", "rm", `\brm\b`},
		{"allow", "swift-format", `\bswift-format\b`},
		{"allow", "python3", `\bpython3\b`},
		{"allow", "my_tool", `\bmy_tool\b`},
		{"allow", `rm\b`, `rm\b`},           // already has metacharacter
		{"allow", `GH_TOKEN=`, `GH_TOKEN=`}, // = is not bare-word
		{"allow", `\[\s`, `\[\s`},           // regex metacharacter
		{"tools", "Bash", "Bash"},           // tools unchanged
		{"tools", "rm", "rm"},               // tools unchanged even for bare word
		{"allow", "", ""},                   // empty is not a bare word
	}
	for _, tt := range tests {
		got := config.Canonicalize(tt.section, tt.value)
		if got != tt.want {
			t.Errorf("Canonicalize(%q, %q) = %q, want %q", tt.section, tt.value, got, tt.want)
		}
	}
}

func TestBareWordRoundTrip(t *testing.T) {
	t.Run("add bare word stores with boundaries", func(t *testing.T) {
		path := writeTmp(t, multiLineConf)
		added, err := config.AddEntry(path, "allow", "cargo")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !added {
			t.Fatal("expected added=true")
		}
		data, _ := os.ReadFile(path)
		if !strings.Contains(string(data), `'\bcargo\b'`) {
			t.Errorf("expected '\\bcargo\\b' in config, got:\n%s", data)
		}
	})

	t.Run("remove bare word finds canonicalized entry", func(t *testing.T) {
		path := writeTmp(t, multiLineConf)
		if _, err := config.AddEntry(path, "allow", "cargo"); err != nil {
			t.Fatal(err)
		}
		removed, err := config.RemoveEntry(path, "allow", "cargo")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !removed {
			t.Fatal("expected removed=true")
		}
		data, _ := os.ReadFile(path)
		if strings.Contains(string(data), "cargo") {
			t.Errorf("expected 'cargo' to be fully removed, got:\n%s", data)
		}
	})

	t.Run("duplicate bare word returns false", func(t *testing.T) {
		path := writeTmp(t, multiLineConf)
		if _, err := config.AddEntry(path, "allow", "cargo"); err != nil {
			t.Fatal(err)
		}
		added, err := config.AddEntry(path, "allow", "cargo")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if added {
			t.Fatal("expected added=false for duplicate bare word")
		}
	})

	t.Run("pattern with metacharacter is not double-wrapped", func(t *testing.T) {
		path := writeTmp(t, multiLineConf)
		added, err := config.AddEntry(path, "allow", `rm\b`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !added {
			t.Fatal("expected added=true")
		}
		data, _ := os.ReadFile(path)
		text := string(data)
		if !strings.Contains(text, `'rm\b'`) {
			t.Errorf("expected 'rm\\b' in config, got:\n%s", text)
		}
		if strings.Contains(text, `'\brm\b'`) {
			t.Errorf("pattern with existing metacharacter was incorrectly double-wrapped: %s", text)
		}
	})

	t.Run("deny bare word stores with boundaries", func(t *testing.T) {
		path := writeTmp(t, multiLineConf)
		added, err := config.AddEntry(path, "deny", "rm")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !added {
			t.Fatal("expected added=true")
		}
		data, _ := os.ReadFile(path)
		if !strings.Contains(string(data), `'\brm\b'`) {
			t.Errorf("expected '\\brm\\b' in deny, got:\n%s", data)
		}
	})
}
