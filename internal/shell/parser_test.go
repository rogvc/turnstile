package shell_test

import (
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/rogvc/turnstile/internal/shell"
)

func TestExtractSubshells(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		bodies []string
		outer  string
	}{
		{
			name:   "no subshell fast path",
			input:  "ls -la",
			bodies: nil,
			outer:  "ls -la",
		},
		{
			name:   "simple subshell",
			input:  "echo $(pwd)",
			bodies: []string{"pwd"},
			outer:  "echo __SUBSHELL__",
		},
		{
			name:   "nested subshell",
			input:  "echo $(echo $(pwd))",
			bodies: []string{"echo $(pwd)"},
			outer:  "echo __SUBSHELL__",
		},
		{
			name:   "multiple subshells",
			input:  "echo $(pwd) $(whoami)",
			bodies: []string{"pwd", "whoami"},
			outer:  "echo __SUBSHELL__ __SUBSHELL__",
		},
		{
			name:   "single-quoted content not extracted",
			input:  "echo '$(not a subshell)'",
			bodies: nil,
			outer:  "echo '$(not a subshell)'",
		},
		{
			name:   "subshell after single quote",
			input:  "echo 'literal' $(pwd)",
			bodies: []string{"pwd"},
			outer:  "echo 'literal' __SUBSHELL__",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bodies, outer := shell.ExtractSubshells(tt.input)
			if !reflect.DeepEqual(bodies, tt.bodies) {
				t.Errorf("bodies: got %v, want %v", bodies, tt.bodies)
			}
			if outer != tt.outer {
				t.Errorf("outer: got %q, want %q", outer, tt.outer)
			}
		})
	}
}

func TestRemoveQuotedContent(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "no quotes fast path",
			input: "ls -la",
			want:  "ls -la",
		},
		{
			name:  "double-quoted operators masked",
			input: `echo "a > b"`,
			want:  `echo "_____"`,
		},
		{
			name:  "single-quoted operators masked",
			input: "echo 'a | b'",
			want:  "echo '_____'",
		},
		{
			name:  "escaped double-quote inside double quotes",
			input: `echo "say \"hi\""`,
			want:  `echo "__________"`,
		},
		{
			name:  "escaped dollar inside double quotes",
			input: `echo "\$HOME"`,
			want:  `echo "______"`,
		},
		{
			name:  "outside-quote content unchanged",
			input: `ls | grep "foo"`,
			want:  `ls | grep "___"`,
		},
		{
			name:  "unterminated quote consumes rest",
			input: `echo "unclosed`,
			want:  `echo "________`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shell.RemoveQuotedContent(tt.input)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFindSplitBoundaries(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  [][2]int
	}{
		{
			name:  "no delimiters",
			input: "ls -la",
			want:  nil,
		},
		{
			name:  "pipe",
			input: "ls | grep foo",
			want:  [][2]int{{3, 4}},
		},
		{
			name:  "or-or",
			input: "cmd1 || cmd2",
			want:  [][2]int{{5, 7}},
		},
		{
			name:  "and-and",
			input: "cmd1 && cmd2",
			want:  [][2]int{{5, 7}},
		},
		{
			name:  "semicolon",
			input: "cmd1; cmd2",
			want:  [][2]int{{4, 5}},
		},
		{
			name:  "newline",
			input: "cmd1\ncmd2",
			want:  [][2]int{{4, 5}},
		},
		{
			name:  "solo ampersand not a delimiter",
			input: "cmd1 & cmd2",
			want:  nil,
		},
		{
			name:  "pipe inside double quotes skipped",
			input: `echo "a|b"`,
			want:  nil,
		},
		{
			name:  "pipe inside single quotes skipped",
			input: "echo 'a|b'",
			want:  nil,
		},
		{
			name:  "multiple delimiters",
			input: "a | b && c; d",
			want:  [][2]int{{2, 3}, {6, 8}, {10, 11}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shell.FindSplitBoundaries(tt.input)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSplitPipeline(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "single command",
			input: "ls -la",
			want:  []string{"ls -la"},
		},
		{
			name:  "pipe chain",
			input: "ls | grep foo",
			want:  []string{"ls", "grep foo"},
		},
		{
			name:  "semicolon chain",
			input: "ls; pwd; echo hi",
			want:  []string{"ls", "pwd", "echo hi"},
		},
		{
			name:  "env var prefix stripped",
			input: "FOO=bar git status",
			want:  []string{"git status"},
		},
		{
			name:  "multiple env var prefixes stripped",
			input: "A=1 B=2 ls",
			want:  []string{"ls"},
		},
		{
			name:  "segment starting with # skipped",
			input: "ls | # comment | pwd",
			want:  []string{"ls", "pwd"},
		},
		{
			name:  "leading paren stripped",
			input: "(ls -la)",
			want:  []string{"ls -la)"},
		},
		{
			name:  "flag-only segment appended to previous",
			input: "ls | -la",
			want:  []string{"ls -la"},
		},
		{
			name:  "empty input",
			input: "",
			want:  []string{},
		},
		{
			name:  "whitespace-only",
			input: "   ",
			want:  []string{},
		},
		{
			name:  "backslash-only segment dropped",
			input: "ls | \\ | pwd",
			want:  []string{"ls", "pwd"},
		},
		{
			// A standalone FOO=bar (no trailing command) is kept as a segment;
			// it matches the \w+= allow pattern so the gate passes it through.
			name:  "standalone env-var assignment kept",
			input: "FOO=bar | ls",
			want:  []string{"FOO=bar", "ls"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shell.SplitPipeline(tt.input)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStripExemptPaths(t *testing.T) {
	// docker-volume example: -v / --volume flag with source:dest mount spec.
	dockerFlagRE := regexp.MustCompile(`(?:--volume=|--volume\s+|-v\s+)(\S+)`)
	exempt := []string{"/tmp", "/var/tmp"}
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "safe /tmp path replaced",
			input: "docker run -v /tmp/build:/build alpine",
			want:  "docker run __SAFE_PATH__ alpine",
		},
		{
			name:  "safe /var/tmp path replaced",
			input: "docker run -v /var/tmp/x:/x alpine",
			want:  "docker run __SAFE_PATH__ alpine",
		},
		{
			name:  "unsafe /etc path not replaced",
			input: "docker run -v /etc:/etc alpine",
			want:  "docker run -v /etc:/etc alpine",
		},
		{
			name:  "traversal /tmp/../etc not replaced",
			input: "docker run -v /tmp/../etc:/e alpine",
			want:  "docker run -v /tmp/../etc:/e alpine",
		},
		{
			name:  "--volume= form replaced",
			input: "docker run --volume=/tmp/x:/x alpine",
			want:  "docker run __SAFE_PATH__ alpine",
		},
		{
			name:  "--volume space form replaced",
			input: "docker run --volume /tmp/x:/x alpine",
			want:  "docker run __SAFE_PATH__ alpine",
		},
		{
			name:  "no matching flag unchanged",
			input: "docker run alpine",
			want:  "docker run alpine",
		},
		{
			name:  "empty exempt list — nothing replaced",
			input: "docker run -v /tmp/x:/x alpine",
			want:  "docker run -v /tmp/x:/x alpine",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ex := exempt
			if strings.Contains(tt.name, "empty exempt") {
				ex = nil
			}
			got := shell.StripExemptPaths(tt.input, dockerFlagRE, ex)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestStripWrappers(t *testing.T) {
	tests := []struct {
		name  string
		input string
		extra []string
		want  string
	}{
		{
			name:  "no wrapper",
			input: "git status",
			want:  "git status",
		},
		{
			name:  "timeout with duration",
			input: "timeout 30 npm test",
			want:  "npm test",
		},
		{
			name:  "timeout with suffix duration",
			input: "timeout 5m go build .",
			want:  "go build .",
		},
		{
			name:  "time",
			input: "time git status",
			want:  "git status",
		},
		{
			name:  "nice no flags",
			input: "nice git status",
			want:  "git status",
		},
		{
			name:  "nice with -n flag",
			input: "nice -n 10 git status",
			want:  "git status",
		},
		{
			name:  "nohup",
			input: "nohup ./server",
			want:  "./server",
		},
		{
			name:  "stdbuf with flag",
			input: "stdbuf -oL npm test",
			want:  "npm test",
		},
		{
			name:  "stdbuf without flags not stripped",
			input: "stdbuf npm test",
			want:  "stdbuf npm test",
		},
		{
			name:  "xargs bare stripped",
			input: "xargs grep pattern",
			want:  "grep pattern",
		},
		{
			name:  "xargs with flag not stripped",
			input: "xargs -n1 grep pattern",
			want:  "xargs -n1 grep pattern",
		},
		{
			name:  "nested wrappers stripped iteratively",
			input: "timeout 5 nohup ./run",
			want:  "./run",
		},
		{
			name:  "user-defined extra wrapper",
			input: "devbox run npm test",
			extra: []string{"devbox run"},
			want:  "npm test",
		},
		{
			name:  "unknown command unchanged",
			input: "myapp --flag arg",
			want:  "myapp --flag arg",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shell.StripWrappers(tt.input, tt.extra)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractHeredocs(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
		ok    bool
	}{
		{
			name:  "no heredoc fast path",
			input: "echo hello",
			want:  "echo hello",
			ok:    true,
		},
		{
			name:  "basic heredoc body stripped",
			input: "python3 <<EOF\nimport json\nprint('hi')\nEOF",
			want:  "python3 <<EOF",
			ok:    true,
		},
		{
			name:  "strip-tabs form",
			input: "cat <<-EOF\n\thello\nEOF",
			want:  "cat <<-EOF",
			ok:    true,
		},
		{
			name:  "quoted delimiter",
			input: "cat <<'EOF'\nhello\nEOF",
			want:  "cat <<'EOF'",
			ok:    true,
		},
		{
			name:  "double-quoted delimiter",
			input: "cat <<\"EOF\"\nhello\nEOF",
			want:  "cat <<\"EOF\"",
			ok:    true,
		},
		{
			name:  "heredoc in compound command",
			input: "echo start && cat <<EOF\nbody\nEOF\necho end",
			want:  "echo start && cat <<EOF\necho end",
			ok:    true,
		},
		{
			name:  "multiple heredocs on one line",
			input: "cmd <<A <<B\nbodyA\nA\nbodyB\nB",
			want:  "cmd <<A <<B",
			ok:    true,
		},
		{
			name:  "unterminated heredoc returns false",
			input: "cat <<EOF\nbody without terminator",
			want:  "cat <<EOF",
			ok:    false,
		},
		{
			name:  "here-string not treated as heredoc",
			input: "cat <<< 'literal string'",
			want:  "cat <<< 'literal string'",
			ok:    true,
		},
		{
			name:  "heredoc opener inside single quotes is ignored",
			input: "echo '<<EOF'",
			want:  "echo '<<EOF'",
			ok:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := shell.ExtractHeredocs(tt.input)
			if ok != tt.ok {
				t.Errorf("ok: got %v, want %v", ok, tt.ok)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestStripComments(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "no comment",
			input: "ls -la",
			want:  "ls -la",
		},
		{
			name:  "comment-only line removed",
			input: "# this is a comment\nls",
			want:  "ls",
		},
		{
			name:  "indented comment removed",
			input: "  # indented\nls",
			want:  "ls",
		},
		{
			name:  "comment between commands removed",
			input: "ls\n# comment\npwd",
			want:  "ls\npwd",
		},
		{
			name:  "inline hash after command not removed",
			input: "ls # inline",
			want:  "ls # inline",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shell.StripComments(tt.input)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestJoinContinuations(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "no continuation",
			input: "ls -la",
			want:  "ls -la",
		},
		{
			name:  "single continuation",
			input: "ls \\\n-la",
			want:  "ls  -la",
		},
		{
			name:  "multiple continuations",
			input: "git \\\ncommit \\\n-m 'msg'",
			want:  "git  commit  -m 'msg'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shell.JoinContinuations(tt.input)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
