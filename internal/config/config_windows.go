//go:build windows

package config

import "os"

// noFollowFlag is 0 on Windows: O_NOFOLLOW does not exist. Symlink protection
// in seed() relies on the Lstat fallback below.
const noFollowFlag = 0

// verifyOwnership is a no-op on Windows. POSIX UID ownership semantics do not
// apply, and resolve() already runs the path through EvalSymlinks before
// reaching here, which neutralises symlink-redirection attacks for our purpose.
func verifyOwnership(_ string, _ os.FileInfo) error {
	return nil
}
