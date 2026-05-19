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
