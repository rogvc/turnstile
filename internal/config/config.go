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

type raw struct {
	Allow         []string `toml:"allow"`
	Deny          []string `toml:"deny"`
	Tools         []string `toml:"tools"`
	StripWrappers []string `toml:"stripWrappers"`
}

// Config holds compiled rules loaded from the config file.
type Config struct {
	AllowRE       *regexp.Regexp
	DenyRE        *regexp.Regexp
	DenyREs       []*regexp.Regexp // individual patterns, for accurate deny reporting
	Tools         map[string]struct{}
	StripWrappers []string // user-defined command names to strip in addition to builtins
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
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, defaultConfig, 0o644); err != nil {
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

	var denyRE *regexp.Regexp
	var denyREs []*regexp.Regexp
	if len(r.Deny) > 0 {
		denyGroups := make([]string, len(r.Deny))
		for i, p := range r.Deny {
			denyGroups[i] = "(?:" + p + ")"
		}
		denyRE, err = regexp.Compile(strings.Join(denyGroups, "|"))
		if err != nil {
			return nil, fmt.Errorf("compile deny: %w", err)
		}
		denyREs = make([]*regexp.Regexp, len(r.Deny))
		for i, p := range r.Deny {
			denyREs[i], err = regexp.Compile(p)
			if err != nil {
				return nil, fmt.Errorf("compile deny pattern %q: %w", p, err)
			}
		}
	} else {
		denyRE = regexp.MustCompile(`[^\s\S]`)
	}

	tools := make(map[string]struct{}, len(r.Tools))
	for _, t := range r.Tools {
		tools[t] = struct{}{}
	}

	// Validate that no user-defined wrapper name also appears in the deny list —
	// stripping a denied command name would bypass the deny check.
	for _, w := range r.StripWrappers {
		if denyRE.MatchString(w) {
			return nil, fmt.Errorf("stripWrappers entry %q overlaps with deny list", w)
		}
	}

	return &Config{
		AllowRE:       allowRE,
		DenyRE:        denyRE,
		DenyREs:       denyREs,
		Tools:         tools,
		StripWrappers: r.StripWrappers,
	}, nil
}
