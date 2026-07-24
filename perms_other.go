//go:build !unix

package main

import "log/slog"

// checkConfigPermissions is a no-op on non-unix platforms, where file ownership and POSIX mode
// bits are not meaningful for sshd configuration. Permission auditing and -fix-perms are only
// supported on unix (see perms.go).
func checkConfigPermissions(_ config, _ bool, _ *result) {
	slog.Debug("file permission checks are only supported on unix platforms")
}
