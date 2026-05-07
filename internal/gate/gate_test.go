package gate_test

import (
	"testing"

	"github.com/rogvc/turnstile/internal/config"
	"github.com/rogvc/turnstile/internal/gate"
)

// testGate creates a Gate with a minimal, deterministic config for testing.
func testGate(t *testing.T) *gate.Gate {
	t.Helper()
	cfg, err := config.Compile(
		[]string{
			`git\b`, `ls\b`, `grep\b`, `pwd\b`, `echo\b`, `cat\b`,
			`__SUBSHELL__\b`, `\w+=`,
		},
		[]string{`sudo\b`, `rm\s+-rf\s+/`, `passwd\b`},
		[]string{"Read", "Write"},
	)
	if err != nil {
		t.Fatalf("compile test config: %v", err)
	}
	return gate.New(cfg)
}

func bash(cmd string) map[string]any {
	return map[string]any{"command": cmd}
}

func TestDecide_NonBash(t *testing.T) {
	g := testGate(t)

	t.Run("tool in allowlist", func(t *testing.T) {
		dec, reason := g.Decide("Read", map[string]any{})
		if dec != "allow" || reason != "" {
			t.Errorf("got (%q, %q), want (allow, \"\")", dec, reason)
		}
	})

	t.Run("tool not in allowlist", func(t *testing.T) {
		dec, reason := g.Decide("UnknownTool", map[string]any{})
		if dec != "ask" {
			t.Errorf("got decision %q, want ask", dec)
		}
		if reason == "" {
			t.Error("expected non-empty reason for unknown tool")
		}
	})
}

func TestDecide_Bash_Empty(t *testing.T) {
	g := testGate(t)

	t.Run("empty command string", func(t *testing.T) {
		dec, _ := g.Decide("Bash", bash(""))
		if dec != "ask" {
			t.Errorf("got %q, want ask", dec)
		}
	})

	t.Run("missing command key", func(t *testing.T) {
		dec, _ := g.Decide("Bash", map[string]any{})
		if dec != "ask" {
			t.Errorf("got %q, want ask", dec)
		}
	})
}

func TestDecide_Bash_Backtick(t *testing.T) {
	g := testGate(t)
	dec, reason := g.Decide("Bash", bash("echo `pwd`"))
	if dec != "ask" {
		t.Errorf("got decision %q, want ask", dec)
	}
	if reason == "" {
		t.Error("expected reason for backtick command")
	}
}

func TestDecide_Bash_Allow(t *testing.T) {
	g := testGate(t)
	cases := []string{
		"ls -la",
		"git status",
		"git log --oneline",
		"ls | grep foo",
		"ls && pwd",
		"echo hello",
		"cat /etc/hosts",
		"result=ok",
	}
	for _, cmd := range cases {
		t.Run(cmd, func(t *testing.T) {
			dec, reason := g.Decide("Bash", bash(cmd))
			if dec != "allow" {
				t.Errorf("got (%q, %q), want allow", dec, reason)
			}
		})
	}
}

func TestDecide_Bash_Deny(t *testing.T) {
	g := testGate(t)
	cases := []string{
		"sudo rm -rf /",
		"sudo apt install vim",
		"passwd root",
	}
	for _, cmd := range cases {
		t.Run(cmd, func(t *testing.T) {
			dec, _ := g.Decide("Bash", bash(cmd))
			if dec != "deny" {
				t.Errorf("got %q, want deny", dec)
			}
		})
	}
}

func TestDecide_Bash_DenyBeatsAsk(t *testing.T) {
	g := testGate(t)
	// unknown_cmd appears before sudo; deny must still win.
	dec, _ := g.Decide("Bash", bash("unknown_cmd foo | sudo rm -rf /"))
	if dec != "deny" {
		t.Errorf("got %q, want deny — deny should take priority over ask", dec)
	}
}

func TestDecide_Bash_Ask_Unknown(t *testing.T) {
	g := testGate(t)
	cases := []string{
		"unknown_cmd",
		"ls | badcmd arg",
	}
	for _, cmd := range cases {
		t.Run(cmd, func(t *testing.T) {
			dec, _ := g.Decide("Bash", bash(cmd))
			if dec != "ask" {
				t.Errorf("got %q, want ask", dec)
			}
		})
	}
}

func TestDecide_Bash_CommentStripped(t *testing.T) {
	g := testGate(t)
	// A command that consists only of a comment line reduces to nothing.
	dec, reason := g.Decide("Bash", bash("# just a comment"))
	if dec != "ask" {
		t.Errorf("got (%q, %q), want ask (could not parse)", dec, reason)
	}
}

func TestDecide_Bash_LineContinuation(t *testing.T) {
	g := testGate(t)
	dec, reason := g.Decide("Bash", bash("git \\\nstatus"))
	if dec != "allow" {
		t.Errorf("got (%q, %q), want allow", dec, reason)
	}
}

func TestDecide_Bash_Subshell(t *testing.T) {
	g := testGate(t)

	t.Run("safe subshell", func(t *testing.T) {
		dec, reason := g.Decide("Bash", bash("echo $(pwd)"))
		if dec != "allow" {
			t.Errorf("got (%q, %q), want allow", dec, reason)
		}
	})

	t.Run("denied command in subshell", func(t *testing.T) {
		dec, _ := g.Decide("Bash", bash("echo $(sudo su)"))
		if dec != "ask" {
			t.Errorf("got %q, want ask", dec)
		}
	})

	t.Run("unknown command in subshell", func(t *testing.T) {
		dec, _ := g.Decide("Bash", bash("echo $(unknown_cmd)"))
		if dec != "ask" {
			t.Errorf("got %q, want ask", dec)
		}
	})

	t.Run("nesting beyond depth limit returns deny", func(t *testing.T) {
		// 6 levels of $(...) exceeds the depth-5 guard.
		cmd := "echo $(echo $(echo $(echo $(echo $(echo $(echo hello))))))"
		dec, _ := g.Decide("Bash", bash(cmd))
		if dec != "deny" {
			t.Errorf("got %q, want deny for deeply nested subshells", dec)
		}
	})

	t.Run("arithmetic subshell safe", func(t *testing.T) {
		dec, reason := g.Decide("Bash", bash("echo $((1 + 2))"))
		if dec != "allow" {
			t.Errorf("got (%q, %q), want allow for arithmetic subshell", dec, reason)
		}
	})
}

func TestDecide_Bash_Redirect(t *testing.T) {
	g := testGate(t)

	t.Run("redirect to /dev/null is safe", func(t *testing.T) {
		dec, reason := g.Decide("Bash", bash("ls > /dev/null"))
		if dec != "allow" {
			t.Errorf("got (%q, %q), want allow", dec, reason)
		}
	})

	t.Run("2>&1 is safe", func(t *testing.T) {
		dec, reason := g.Decide("Bash", bash("ls 2>&1"))
		if dec != "allow" {
			t.Errorf("got (%q, %q), want allow", dec, reason)
		}
	})

	t.Run("redirect to file asks", func(t *testing.T) {
		dec, _ := g.Decide("Bash", bash("ls > /tmp/output.txt"))
		if dec != "ask" {
			t.Errorf("got %q, want ask", dec)
		}
	})

	t.Run("append redirect asks", func(t *testing.T) {
		dec, _ := g.Decide("Bash", bash("echo hi >> /tmp/log.txt"))
		if dec != "ask" {
			t.Errorf("got %q, want ask", dec)
		}
	})

	t.Run("redirect inside subshell asks", func(t *testing.T) {
		dec, _ := g.Decide("Bash", bash("echo $(cat /etc/hosts > /tmp/stolen)"))
		if dec != "ask" {
			t.Errorf("got %q, want ask", dec)
		}
	})
}

func TestDecide_Bash_QuoteAwareDeny(t *testing.T) {
	g := testGate(t)

	t.Run("deny token inside single-quoted arg is not denied", func(t *testing.T) {
		// printf is in the allow list; "sudo" is only inside a quoted string.
		dec, _ := g.Decide("Bash", bash(`printf '{"command":"sudo apt update"}'`))
		if dec == "deny" {
			t.Error("got deny — quoted deny token should not trigger")
		}
	})

	t.Run("deny token inside double-quoted arg is not denied", func(t *testing.T) {
		dec, _ := g.Decide("Bash", bash(`echo "sudo is a shell command"`))
		if dec == "deny" {
			t.Error("got deny — double-quoted deny token should not trigger")
		}
	})

	t.Run("unquoted deny token still denied", func(t *testing.T) {
		dec, _ := g.Decide("Bash", bash("sudo apt update"))
		if dec != "deny" {
			t.Errorf("got %q, want deny for unquoted sudo", dec)
		}
	})

	t.Run("deny token in double-quoted flag value is not denied", func(t *testing.T) {
		dec, _ := g.Decide("Bash", bash(`echo --flag "passwd root"`))
		if dec == "deny" {
			t.Error("got deny — quoted passwd in flag value should not trigger")
		}
	})
}

func TestDecide_Bash_Heredoc(t *testing.T) {
	g := testGate(t)

	t.Run("heredoc in subshell is not validated", func(t *testing.T) {
		// Any heredoc inside $(...) is treated as unsafe — the body content
		// reaches the interpreter without pattern matching.
		cmd := "git commit -m $(cat <<EOF\nhello\nEOF\n)"
		dec, _ := g.Decide("Bash", bash(cmd))
		if dec != "ask" {
			t.Errorf("got %q, want ask for heredoc in subshell", dec)
		}
	})

	t.Run("heredoc with denied command asks", func(t *testing.T) {
		cmd := "result=$(sudo su <<EOF\nstuff\nEOF\n)"
		dec, _ := g.Decide("Bash", bash(cmd))
		if dec != "ask" {
			t.Errorf("got %q, want ask", dec)
		}
	})
}
