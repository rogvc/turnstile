// Package config loads and compiles turnstile policy rules from a TOML file.
package config

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
)

//go:embed config.toml
var defaultConfig []byte

// PathExemption describes a set of source paths that are exempt from a
// deny rule, identified by a flag-pattern regex (e.g. for docker -v / --volume).
type PathExemption struct {
	Scope       string         `toml:"scope"`       // descriptive label
	FlagPattern string         `toml:"flagPattern"` // regex with one capture group for the path
	Paths       []string       `toml:"paths"`
	FlagRE      *regexp.Regexp // compiled from FlagPattern; not decoded from TOML
}

type raw struct {
	Allow              []string        `toml:"allow"`
	Deny               []string        `toml:"deny"`
	Tools              []string        `toml:"tools"`
	StripWrappers      []string        `toml:"stripWrappers"`
	SafePathExemptions []PathExemption `toml:"safePathExemptions"`
}

// Config holds compiled rules loaded from the config file.
type Config struct {
	AllowRE            *regexp.Regexp
	DenyREs            []*regexp.Regexp // one entry per deny pattern; used for both matching and reporting
	Tools              map[string]struct{}
	StripWrappers      []string
	SafePathExemptions []PathExemption
}

// Denies reports whether s matches any deny pattern.
func (c *Config) Denies(s string) bool {
	for _, re := range c.DenyREs {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

// Load resolves, seeds if absent, and returns compiled config.
func Load() (*Config, error) {
	path, err := resolve()
	if err != nil {
		return nil, err
	}
	if err := seed(path); err != nil {
		return nil, err
	}
	var r raw
	if _, err := toml.DecodeFile(path, &r); err != nil {
		return nil, fmt.Errorf("load %s: %w", path, err)
	}
	return compile(path, &r)
}

// Compile builds a Config from raw string slices without filesystem access.
func Compile(allow, deny, tools []string) (*Config, error) {
	return compile("in-memory", &raw{Allow: allow, Deny: deny, Tools: tools})
}

func resolve() (string, error) {
	if p := os.Getenv("TURNSTILE_CONFIG"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config dir: %w", err)
	}
	return filepath.Join(dir, "turnstile", "config.toml"), nil
}

func seed(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, defaultConfig, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func compile(path string, r *raw) (*Config, error) {
	if len(r.Allow) == 0 {
		return nil, fmt.Errorf("%s: allow is empty", path)
	}
	groups := make([]string, len(r.Allow))
	for i, p := range r.Allow {
		groups[i] = "(?:" + p + ")"
	}
	allowRE, err := regexp.Compile("^(?:" + strings.Join(groups, "|") + ")")
	if err != nil {
		return nil, fmt.Errorf("compile allow: %w", err)
	}

	denyREs := make([]*regexp.Regexp, len(r.Deny))
	for i, p := range r.Deny {
		denyREs[i], err = regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("compile deny pattern %q: %w", p, err)
		}
	}

	tools := make(map[string]struct{}, len(r.Tools))
	for _, t := range r.Tools {
		tools[t] = struct{}{}
	}

	// Validate that no user-defined wrapper name also appears in the deny list.
	for _, w := range r.StripWrappers {
		for _, re := range denyREs {
			if re.MatchString(w) {
				return nil, fmt.Errorf("stripWrappers entry %q overlaps with deny list", w)
			}
		}
	}

	exemptions := make([]PathExemption, len(r.SafePathExemptions))
	for i, ex := range r.SafePathExemptions {
		if ex.FlagPattern == "" {
			return nil, fmt.Errorf("safePathExemptions[%d] (scope %q): flagPattern is required", i, ex.Scope)
		}
		flagRE, err := regexp.Compile(ex.FlagPattern)
		if err != nil {
			return nil, fmt.Errorf("safePathExemptions[%d] (scope %q): %w", i, ex.Scope, err)
		}
		exemptions[i] = PathExemption{
			Scope:       ex.Scope,
			FlagPattern: ex.FlagPattern,
			Paths:       ex.Paths,
			FlagRE:      flagRE,
		}
	}

	return &Config{
		AllowRE:            allowRE,
		DenyREs:            denyREs,
		Tools:              tools,
		StripWrappers:      r.StripWrappers,
		SafePathExemptions: exemptions,
	}, nil
}
