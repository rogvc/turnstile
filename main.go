package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/rogvc/turnstile/internal/config"
	"github.com/rogvc/turnstile/internal/gate"
)

type hookOutput struct {
	EventName string `json:"hookEventName"`
	Decision  string `json:"permissionDecision"`
	Reason    string `json:"permissionDecisionReason,omitempty"`
}

type envelope struct {
	Output hookOutput `json:"hookSpecificOutput"`
}

type hookInput struct {
	ToolName  string         `json:"tool_name"`
	ToolInput map[string]any `json:"tool_input"`
}

func emit(decision, reason string) {
	env := envelope{Output: hookOutput{
		EventName: "PreToolUse",
		Decision:  decision,
		Reason:    reason,
	}}
	out, _ := json.Marshal(env)
	fmt.Println(string(out))
}

func main() {
	var (
		testCmd  string
		testTool string
		testJSON bool
	)
	flag.StringVar(&testCmd, "test", "", "preview the gate decision for a Bash command without constructing JSON")
	flag.StringVar(&testCmd, "t", "", "shorthand for --test")
	flag.StringVar(&testTool, "test-tool", "Bash", "tool_name to use with --test (default: Bash)")
	flag.BoolVar(&testJSON, "test-json", false, "emit raw hookSpecificOutput JSON instead of pretty output with --test")
	flag.Parse()

	cfg, err := config.Load()
	if err != nil {
		if testCmd != "" {
			fmt.Fprintf(os.Stderr, "config error: %v\n", err)
			os.Exit(1)
		}
		emit("ask", "config error: "+err.Error())
		return
	}

	if testCmd != "" {
		decision, reason := gate.New(cfg).Decide(testTool, map[string]any{"command": testCmd})
		if testJSON {
			emit(decision, reason)
		} else if reason != "" {
			fmt.Printf("%s: %s\n", decision, reason)
		} else {
			fmt.Println(decision)
		}
		switch decision {
		case "allow":
			os.Exit(0)
		case "ask":
			os.Exit(1)
		default: // deny
			os.Exit(2)
		}
	}

	var data hookInput
	if err := json.NewDecoder(os.Stdin).Decode(&data); err != nil {
		emit("ask", "Failed to parse hook input")
		return
	}
	decision, reason := gate.New(cfg).Decide(data.ToolName, data.ToolInput)
	emit(decision, reason)
}
