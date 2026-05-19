//go:build unix

package config

import (
	"fmt"
	"os"
	"syscall"
)

const noFollowFlag = syscall.O_NOFOLLOW

func verifyOwnership(path string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("TURNSTILE_CONFIG: cannot retrieve ownership information")
	}
	euid := os.Geteuid()
	if euid < 0 || stat.Uid != uint32(euid) { //nolint:gosec // euid range guarded above
		return fmt.Errorf("TURNSTILE_CONFIG path %q is owned by UID %d, not current user %d", path, stat.Uid, euid)
	}
	return nil
}
