// Package config loads and compiles turnstile policy rules from a TOML file.
package config

import (
	_ "embed"
	"encoding/gob"
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
	Scope       string         `toml:"scope"`        // descriptive label
	FlagPattern string         `toml:"flag_pattern"` // regex with one capture group for the path
	Paths       []string       `toml:"paths"`
	FlagRE      *regexp.Regexp // compiled from FlagPattern; not decoded from TOML
}

type raw struct {
	Allow                   []string        `toml:"allow"`
	Deny                    []string        `toml:"deny"`
	Tools                   []string        `toml:"tools"`
	ToolsDefaultToDefer     bool            `toml:"tools_default_to_defer"`
	StripWrappers           []string        `toml:"strip_wrappers"`
	SafePathExemptions      []PathExemption `toml:"safe_path_exemptions"`
	ProjectRoots            []string        `toml:"project_roots"`
	SensitiveEnvVars        []string        `toml:"sensitive_env_vars"`
	SensitiveEnvVarPrefixes []string        `toml:"sensitive_env_var_prefixes"`
}

// Config holds compiled rules loaded from the config file.
type Config struct {
	AllowRE                 *regexp.Regexp
	DenyRE                  *regexp.Regexp   // combined alternation for fast matching
	DenyREs                 []*regexp.Regexp // per-pattern slice for extracting which pattern matched
	Tools                   map[string]struct{}
	ToolsDefaultToDefer     bool
	StripWrappers           []string
	SafePathExemptions      []PathExemption
	ProjectRoots            []string
	SensitiveEnvVars        map[string]struct{} // exact-match names excluded from the subshell auto-allow path
	SensitiveEnvVarPrefixes []string            // prefix-match counterparts (LD_, DYLD_, NPM_CONFIG_, …)
}

// cacheData represents the serializable form of a compiled config for gob encoding.
type cacheData struct {
	AllowPattern            string
	DenyPatterns            []string
	ToolsList               []string
	ToolsDefaultToDefer     bool
	StripWrappers           []string
	SafePathExemptions      []cachedPathExemption
	ProjectRoots            []string
	SensitiveEnvVars        []string
	SensitiveEnvVarPrefixes []string
}

// cachedPathExemption is the serializable form of PathExemption without the compiled regex.
type cachedPathExemption struct {
	Scope       string
	FlagPattern string
	Paths       []string
}

// Denies reports whether s matches any deny pattern.
func (c *Config) Denies(s string) bool {
	if c.DenyRE != nil {
		return c.DenyRE.MatchString(s)
	}
	// Fallback for empty deny list
	return false
}

// resolvedPath caches the last resolved config path for redaction purposes.
var resolvedPath string

// ResolvedPath returns the last resolved config path, or empty string if not yet resolved.
func ResolvedPath() string {
	return resolvedPath
}

// Load resolves, seeds if absent, and returns compiled config.
// If a valid cache exists and is newer than the source file, it is used instead of re-parsing.
func Load() (*Config, error) {
	path, fromEnv, err := resolve()
	if err != nil {
		return nil, err
	}
	resolvedPath = path
	if err := seed(path, fromEnv); err != nil {
		return nil, err
	}

	// Try loading from cache first
	cachePath := cachePathFor(path)
	if cfg, ok := tryLoadCache(path, cachePath); ok {
		return cfg, nil
	}

	// Cache miss or invalid: parse and compile from source
	var r raw
	md, err := toml.DecodeFile(path, &r)
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", path, err)
	}
	if len(md.Undecoded()) > 0 {
		return nil, fmt.Errorf("unknown config keys: %v%s", md.Undecoded(), migrationHint(md.Undecoded()))
	}
	cfg, err := compile(path, &r)
	if err != nil {
		return nil, err
	}

	// Save to cache for next time (ignore errors; cache is optional)
	_ = saveCache(cfg, cachePath)

	return cfg, nil
}

// migrationHint formats a hint suggesting renames when an old camelCase key
// is found in the undecoded set. Returns "" when nothing matches.
func migrationHint(keys []toml.Key) string {
	renames := map[string]string{
		"stripWrappers":      "strip_wrappers",
		"safePathExemptions": "safe_path_exemptions",
		"flagPattern":        "flag_pattern",
	}
	var hits []string
	for _, k := range keys {
		s := k.String()
		for old, snake := range renames {
			if s == old || strings.HasSuffix(s, "."+old) {
				hits = append(hits, fmt.Sprintf("%s -> %s", old, snake))
			}
		}
	}
	if len(hits) == 0 {
		return ""
	}
	return " (renamed in this release: " + strings.Join(hits, ", ") + ")"
}

// Compile builds a Config from raw string slices without filesystem access.
// SensitiveEnvVars/SensitiveEnvVarPrefixes default to empty; use
// CompileWithOptions to supply them.
func Compile(allow, deny, tools []string) (*Config, error) {
	return compile("in-memory", &raw{Allow: allow, Deny: deny, Tools: tools})
}

// CompileOptions carries the optional fields a caller may set without changing
// the positional Compile signature. Zero-valued fields are ignored.
type CompileOptions struct {
	SensitiveEnvVars        []string
	SensitiveEnvVarPrefixes []string
}

// CompileWithOptions is Compile plus optional fields. Tests for the
// subshell-assignment guard use this to inject the sensitive-var lists.
func CompileWithOptions(allow, deny, tools []string, opts CompileOptions) (*Config, error) {
	return compile("in-memory", &raw{
		Allow:                   allow,
		Deny:                    deny,
		Tools:                   tools,
		SensitiveEnvVars:        opts.SensitiveEnvVars,
		SensitiveEnvVarPrefixes: opts.SensitiveEnvVarPrefixes,
	})
}

func resolve() (string, bool, error) {
	if p := os.Getenv("TURNSTILE_CONFIG"); p != "" {
		// Clean the path to remove any directory traversal components
		cleaned := filepath.Clean(p)

		// Evaluate symlinks to get the final path
		resolved, err := filepath.EvalSymlinks(cleaned)
		if err != nil {
			return "", false, fmt.Errorf("resolve TURNSTILE_CONFIG path: %w", err)
		}

		// Verify ownership: the final path must be owned by the current user.
		// On Windows this is a no-op (UID semantics don't apply); EvalSymlinks
		// above already prevents indirection through a symlink farm.
		info, err := os.Stat(resolved)
		if err != nil {
			return "", false, fmt.Errorf("stat TURNSTILE_CONFIG path: %w", err)
		}
		if err := verifyOwnership(resolved, info); err != nil {
			return "", false, err
		}
		return resolved, true, nil
	}
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		var err error
		dir, err = os.UserConfigDir()
		if err != nil {
			return "", false, fmt.Errorf("resolve user config dir: %w", err)
		}
	}
	return filepath.Join(dir, "turnstile", "config.toml"), false, nil
}

func seed(path string, fromEnv bool) error {
	// When path comes from TURNSTILE_CONFIG env, the user must manage the file.
	// Return an error if it doesn't exist rather than auto-creating it.
	if fromEnv {
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("TURNSTILE_CONFIG path %q does not exist: %w", path, err)
		}
		return nil
	}

	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}

	// O_EXCL prevents TOCTOU race; O_NOFOLLOW (Unix only) prevents symlink-squatting.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|noFollowFlag, 0o600) //nolint:gosec // path is the resolved config location, validated above
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			info, lstatErr := os.Lstat(path)
			if lstatErr != nil {
				return fmt.Errorf("lstat %s: %w", path, lstatErr)
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("seed %s: refusing to follow symlink", path)
			}
			return nil
		}
		return fmt.Errorf("create %s: %w", path, err)
	}
	if _, err := f.Write(defaultConfig); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
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
		return nil, fmt.Errorf("compile allow: invalid regex: %w (RE2 does not support lookarounds (?=...) or backreferences \\1; see https://pkg.go.dev/regexp/syntax)", err)
	}

	// Compile individual deny patterns for error messages
	denyREs := make([]*regexp.Regexp, len(r.Deny))
	for i, p := range r.Deny {
		denyREs[i], err = regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("invalid regex %q: %w (RE2 does not support lookarounds (?=...) or backreferences \\1; see https://pkg.go.dev/regexp/syntax)", p, err)
		}
	}

	// Combine deny patterns into a single alternation for fast matching
	var denyRE *regexp.Regexp
	if len(r.Deny) > 0 {
		denyGroups := make([]string, len(r.Deny))
		for i, p := range r.Deny {
			denyGroups[i] = "(?:" + p + ")"
		}
		denyRE, err = regexp.Compile("(?:" + strings.Join(denyGroups, "|") + ")")
		if err != nil {
			return nil, fmt.Errorf("compile deny alternation: invalid regex: %w (RE2 does not support lookarounds (?=...) or backreferences \\1; see https://pkg.go.dev/regexp/syntax)", err)
		}
	}

	tools := make(map[string]struct{}, len(r.Tools))
	for _, t := range r.Tools {
		tools[t] = struct{}{}
	}

	// Filter out any strip_wrappers entries that overlap with deny patterns,
	// emitting a warning to stderr rather than failing the whole load.
	var filteredWrappers []string
	for _, w := range r.StripWrappers {
		overlaps := false
		for _, re := range denyREs {
			if re.MatchString(w) {
				fmt.Fprintf(os.Stderr, "turnstile: warning: strip_wrappers entry %q overlaps with deny list; dropping\n", w)
				overlaps = true
				break
			}
		}
		if !overlaps {
			filteredWrappers = append(filteredWrappers, w)
		}
	}

	exemptions := make([]PathExemption, len(r.SafePathExemptions))
	for i, ex := range r.SafePathExemptions {
		if ex.FlagPattern == "" {
			return nil, fmt.Errorf("safe_path_exemptions[%d] (scope %q): flag_pattern is required", i, ex.Scope)
		}
		flagRE, err := regexp.Compile(ex.FlagPattern)
		if err != nil {
			return nil, fmt.Errorf("safe_path_exemptions[%d] (scope %q): %w", i, ex.Scope, err)
		}
		exemptions[i] = PathExemption{
			Scope:       ex.Scope,
			FlagPattern: ex.FlagPattern,
			Paths:       ex.Paths,
			FlagRE:      flagRE,
		}
	}

	sensitiveEnv := make(map[string]struct{}, len(r.SensitiveEnvVars))
	for _, n := range r.SensitiveEnvVars {
		sensitiveEnv[n] = struct{}{}
	}

	return &Config{
		AllowRE:                 allowRE,
		DenyRE:                  denyRE,
		DenyREs:                 denyREs,
		Tools:                   tools,
		ToolsDefaultToDefer:     r.ToolsDefaultToDefer,
		StripWrappers:           filteredWrappers,
		SafePathExemptions:      exemptions,
		ProjectRoots:            r.ProjectRoots,
		SensitiveEnvVars:        sensitiveEnv,
		SensitiveEnvVarPrefixes: r.SensitiveEnvVarPrefixes,
	}, nil
}

// cachePathFor returns the cache file path for a given config file path.
// For the standard config location, the cache is stored alongside it.
// For custom paths (TURNSTILE_CONFIG), the cache uses the same base name.
func cachePathFor(configPath string) string {
	dir := filepath.Dir(configPath)
	base := filepath.Base(configPath)
	// Remove extension and add .cache.gob suffix
	ext := filepath.Ext(base)
	nameWithoutExt := base[:len(base)-len(ext)]
	return filepath.Join(dir, nameWithoutExt+".cache.gob")
}

// tryLoadCache attempts to load and reconstruct a Config from the cache.
// Returns (cfg, true) if the cache is valid and newer than the source;
// returns (nil, false) otherwise.
func tryLoadCache(sourcePath, cachePath string) (*Config, bool) {
	sourceInfo, err := os.Stat(sourcePath)
	if err != nil {
		return nil, false
	}
	cacheInfo, err := os.Stat(cachePath)
	if err != nil {
		return nil, false
	}

	// Cache must be newer than source and non-empty
	if cacheInfo.ModTime().Before(sourceInfo.ModTime()) || cacheInfo.Size() == 0 {
		return nil, false
	}

	// Attempt to decode the cache
	f, err := os.Open(cachePath) //nolint:gosec // cachePath is derived from the resolved config path
	if err != nil {
		return nil, false
	}
	defer func() { _ = f.Close() }()

	var cd cacheData
	if err := gob.NewDecoder(f).Decode(&cd); err != nil {
		return nil, false
	}

	// Reconstruct the Config from cache data
	cfg, err := reconstructConfig(&cd)
	if err != nil {
		return nil, false
	}

	return cfg, true
}

// saveCache writes a gob-encoded cache of the compiled config.
func saveCache(cfg *Config, cachePath string) error {
	// Ensure cache directory exists
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o750); err != nil {
		return err
	}

	// Extract serializable data from Config
	cd := cacheData{
		AllowPattern:            cfg.AllowRE.String(),
		ToolsDefaultToDefer:     cfg.ToolsDefaultToDefer,
		StripWrappers:           cfg.StripWrappers,
		ProjectRoots:            cfg.ProjectRoots,
		SensitiveEnvVarPrefixes: cfg.SensitiveEnvVarPrefixes,
	}
	cd.SensitiveEnvVars = make([]string, 0, len(cfg.SensitiveEnvVars))
	for n := range cfg.SensitiveEnvVars {
		cd.SensitiveEnvVars = append(cd.SensitiveEnvVars, n)
	}

	// Extract deny patterns
	cd.DenyPatterns = make([]string, len(cfg.DenyREs))
	for i, re := range cfg.DenyREs {
		cd.DenyPatterns[i] = re.String()
	}

	// Extract tools list
	cd.ToolsList = make([]string, 0, len(cfg.Tools))
	for t := range cfg.Tools {
		cd.ToolsList = append(cd.ToolsList, t)
	}

	// Convert path exemptions to cacheable form (without compiled regex)
	cd.SafePathExemptions = make([]cachedPathExemption, len(cfg.SafePathExemptions))
	for i, ex := range cfg.SafePathExemptions {
		cd.SafePathExemptions[i] = cachedPathExemption{
			Scope:       ex.Scope,
			FlagPattern: ex.FlagPattern,
			Paths:       ex.Paths,
		}
	}

	// Write atomically by creating a temp file and renaming
	tmpPath := cachePath + ".tmp"
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) //nolint:gosec // tmpPath is derived from the resolved config path
	if err != nil {
		return err
	}

	encErr := gob.NewEncoder(f).Encode(&cd)
	closeErr := f.Close()
	if encErr != nil {
		_ = os.Remove(tmpPath)
		return encErr
	}
	if closeErr != nil {
		_ = os.Remove(tmpPath)
		return closeErr
	}

	return os.Rename(tmpPath, cachePath)
}

// reconstructConfig rebuilds a Config from cached data by recompiling regexes.
func reconstructConfig(cd *cacheData) (*Config, error) {
	// Recompile allow pattern
	allowRE, err := regexp.Compile(cd.AllowPattern)
	if err != nil {
		return nil, fmt.Errorf("reconstruct allow regex: %w", err)
	}

	// Recompile individual deny patterns
	denyREs := make([]*regexp.Regexp, len(cd.DenyPatterns))
	for i, p := range cd.DenyPatterns {
		denyREs[i], err = regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("reconstruct deny regex %d: %w", i, err)
		}
	}

	// Recompile combined deny pattern
	var denyRE *regexp.Regexp
	if len(cd.DenyPatterns) > 0 {
		denyGroups := make([]string, len(cd.DenyPatterns))
		for i, p := range cd.DenyPatterns {
			denyGroups[i] = "(?:" + p + ")"
		}
		denyRE, err = regexp.Compile("(?:" + strings.Join(denyGroups, "|") + ")")
		if err != nil {
			return nil, fmt.Errorf("reconstruct deny alternation: %w", err)
		}
	}

	// Reconstruct tools map
	tools := make(map[string]struct{}, len(cd.ToolsList))
	for _, t := range cd.ToolsList {
		tools[t] = struct{}{}
	}

	// Recompile FlagRE for each exemption
	exemptions := make([]PathExemption, len(cd.SafePathExemptions))
	for i, ex := range cd.SafePathExemptions {
		flagRE, err := regexp.Compile(ex.FlagPattern)
		if err != nil {
			return nil, fmt.Errorf("reconstruct exemption %d flag pattern: %w", i, err)
		}
		exemptions[i] = PathExemption{
			Scope:       ex.Scope,
			FlagPattern: ex.FlagPattern,
			Paths:       ex.Paths,
			FlagRE:      flagRE,
		}
	}

	sensitiveEnv := make(map[string]struct{}, len(cd.SensitiveEnvVars))
	for _, n := range cd.SensitiveEnvVars {
		sensitiveEnv[n] = struct{}{}
	}

	return &Config{
		AllowRE:                 allowRE,
		DenyRE:                  denyRE,
		DenyREs:                 denyREs,
		Tools:                   tools,
		ToolsDefaultToDefer:     cd.ToolsDefaultToDefer,
		StripWrappers:           cd.StripWrappers,
		SafePathExemptions:      exemptions,
		ProjectRoots:            cd.ProjectRoots,
		SensitiveEnvVars:        sensitiveEnv,
		SensitiveEnvVarPrefixes: cd.SensitiveEnvVarPrefixes,
	}, nil
}
