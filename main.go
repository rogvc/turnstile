// Package main is the turnstile CLI entry point: it serves as a Claude Code
// PreToolUse hook by default, with `add`, `remove`, and `version` subcommands.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/rogvc/turnstile/internal/config"
	"github.com/rogvc/turnstile/internal/gate"
)

// This is to be set at compile time.
const version string = "dev"

func main() {
	if len(os.Args) < 2 {
		runHook()
		return
	}
	switch os.Args[1] {
	case "version", "--version", "-v":
		fmt.Println(version)
	case "add", "remove":
		if err := runEdit(os.Args[1], os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	default:
		runHook()
	}
}

func runHook() {
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

func runEdit(cmd string, args []string) error {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), "usage: turnstile %s <section> <value>\n  section: allow, deny, or tools\n", cmd)
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		fs.Usage()
		return fmt.Errorf("expected <section> <value>, got %d arg(s)", fs.NArg())
	}
	section := fs.Arg(0)
	value := fs.Arg(1)

	path, err := config.ResolveAndSeed()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	display := `"` + value + `"`
	if section != "tools" {
		display = `'` + value + `'`
	}

	switch cmd {
	case "add":
		return runAdd(path, section, value, display)
	case "remove":
		return runRemove(path, section, value, display)
	}
	return nil
}

func runAdd(path, section, value, display string) error {
	added, err := config.AddEntry(path, section, value)
	if err != nil {
		return err
	}
	if added {
		fmt.Printf("added %s to %s in %s\n", display, section, path)
	} else {
		fmt.Printf("%s already contains %s\n", section, display)
	}
	return nil
}

func runRemove(path, section, value, display string) error {
	removed, err := config.RemoveEntry(path, section, value)
	if err != nil {
		return err
	}
	if removed {
		fmt.Printf("removed %s from %s in %s\n", display, section, path)
	} else {
		fmt.Printf("%s does not contain %s\n", section, display)
	}
	return nil
}

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
