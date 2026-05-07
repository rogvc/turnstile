package main

import (
	"encoding/json"
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
	cfg, err := config.Load()
	if err != nil {
		emit("ask", "config error: "+err.Error())
		return
	}
	var data hookInput
	if err := json.NewDecoder(os.Stdin).Decode(&data); err != nil {
		emit("ask", "Failed to parse hook input")
		return
	}
	decision, reason := gate.New(cfg).Decide(data.ToolName, data.ToolInput)
	emit(decision, reason)
}
