//go:build unix

package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
)

// Conventional CIS locations for sshd configuration. The tool does not parse `Include`
// directives, so files pulled in from non-standard locations are not covered.
const (
	sshdConfigPath = "/etc/ssh/sshd_config"
	sshdConfigDir  = "/etc/ssh/sshd_config.d"
)

// sshd config and host keys must be owned by root:root (CIS).
const (
	rootUID = 0
	rootGID = 0
)

// permSeverity classifies how a mode compares against a target's policy.
type permSeverity int

const (
	permOK permSeverity = iota
	permWarn
	permError
)

// permTarget describes the permission policy for one file or directory.
//   - errorMask: permission bits whose presence is a security error (e.g. group/other write, or
//     any group/other access for secret files such as private host keys).
//   - warnMask: additional bits that are merely not-recommended (e.g. group/other read on the
//     non-secret sshd_config).
//
// A fix clears both masks (only ever removing bits, so an already-stricter mode is preserved)
// and sets ownership to root:root.
type permTarget struct {
	path      string
	wantMode  os.FileMode // canonical CIS mode, shown in messages
	errorMask os.FileMode
	warnMask  os.FileMode
}

// checkConfigPermissions audits ownership and mode of the main sshd_config, the sshd_config.d
// drop-in directory and its *.conf files, and the host key pairs discovered from `sshd -T`.
// Too-permissive modes and non-root ownership are recorded as errors; merely not-recommended
// modes and a non-root group are warnings. When fix is true each finding is remediated in place
// (chown root:root, and a chmod that clears the offending bits) and then re-evaluated, so the
// recorded result reflects the post-fix state.
func checkConfigPermissions(c config, fix bool, res *result) {
	slog.Info("verifying file permissions", "fix", fix)
	for _, t := range permTargets(c) {
		checkPermTarget(t, fix, res)
	}
}

// permTargets builds the ordered list of permission targets from the conventional paths and the
// host keys advertised by sshd. Absent optional paths (e.g. no drop-in directory) are skipped.
func permTargets(c config) []permTarget {
	var targets []permTarget

	// Main config: root:root 0600 (CIS 5.2.1). Group/other write is an error; read is a warning.
	targets = append(targets, permTarget{path: sshdConfigPath, wantMode: 0o600, errorMask: 0o022, warnMask: 0o044})

	// Drop-in directory (0755) and its *.conf files (same policy as the main config).
	if fi, err := os.Stat(sshdConfigDir); err == nil && fi.IsDir() {
		targets = append(targets, permTarget{path: sshdConfigDir, wantMode: 0o755, errorMask: 0o022})
		matches, _ := filepath.Glob(filepath.Join(sshdConfigDir, "*.conf"))
		for _, m := range matches {
			targets = append(targets, permTarget{path: m, wantMode: 0o600, errorMask: 0o022, warnMask: 0o044})
		}
	}

	// Host keys from `sshd -T`: private key 0600 (any group/other access is an error, key secrecy);
	// public key 0644 (group/other write is an error, read is expected).
	for _, key := range c["hostkey"] {
		targets = append(targets, permTarget{path: key, wantMode: 0o600, errorMask: 0o077})
		targets = append(targets, permTarget{path: key + ".pub", wantMode: 0o644, errorMask: 0o022})
	}
	return targets
}

// checkPermTarget evaluates a single target (optionally fixing it first) and records findings.
func checkPermTarget(t permTarget, fix bool, res *result) {
	fi, err := os.Lstat(t.path)
	if err != nil {
		slog.Debug("skipping permission check; cannot stat", "path", t.path, "err", err.Error())
		return
	}
	// Never follow or modify a symlink where a regular file/dir is expected.
	if fi.Mode()&os.ModeSymlink != 0 {
		slog.Warn("permission check skipped for symlink", "path", t.path)
		res.warnings++
		return
	}

	if fix {
		fixPermTarget(t, fi)
		if fi2, err := os.Lstat(t.path); err == nil {
			fi = fi2
		}
	}

	uid, gid, ownerKnown := statOwner(fi)
	mode := fi.Mode().Perm()

	if ownerKnown && uid != rootUID {
		slog.Error("not owned by root", "path", t.path, "uid", uid)
		res.errors++
	}
	if ownerKnown && gid != rootGID {
		slog.Warn("group is not root", "path", t.path, "gid", gid)
		res.warnings++
	}

	switch evalMode(mode, t.errorMask, t.warnMask) {
	case permError:
		slog.Error("permissions too permissive", "path", t.path, "mode", modeString(mode), "recommended", modeString(t.wantMode))
		res.errors++
	case permWarn:
		slog.Warn("permissions more permissive than recommended", "path", t.path, "mode", modeString(mode), "recommended", modeString(t.wantMode))
		res.warnings++
	case permOK:
		slog.Info("permissions ok", "path", t.path, "mode", modeString(mode))
	}
}

// evalMode returns the severity of a mode against the error/warn masks.
func evalMode(mode, errorMask, warnMask os.FileMode) permSeverity {
	switch {
	case mode&errorMask != 0:
		return permError
	case mode&warnMask != 0:
		return permWarn
	default:
		return permOK
	}
}

// fixPermTarget tightens ownership and mode to the CIS recommendation. It sets ownership to
// root:root and clears the offending permission bits without ever adding any, so a stricter mode
// than recommended is preserved. Failures are logged, not fatal; the subsequent re-check records
// anything that still fails to comply.
func fixPermTarget(t permTarget, fi os.FileInfo) {
	if uid, gid, ok := statOwner(fi); ok && (uid != rootUID || gid != rootGID) {
		if err := os.Chown(t.path, rootUID, rootGID); err != nil {
			slog.Warn("cannot change owner to root:root", "path", t.path, "err", err.Error())
		} else {
			slog.Info("changed owner to root:root", "path", t.path)
		}
	}
	cur := fi.Mode().Perm()
	want := cur &^ (t.errorMask | t.warnMask)
	if want != cur {
		if err := os.Chmod(t.path, want); err != nil {
			slog.Warn("cannot tighten permissions", "path", t.path, "err", err.Error())
		} else {
			slog.Info("tightened permissions", "path", t.path, "from", modeString(cur), "to", modeString(want))
		}
	}
}

// statOwner returns the owner uid/gid of fi. ok is false when the platform does not expose them.
func statOwner(fi os.FileInfo) (uid, gid int, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}

// modeString renders permission bits as a zero-padded octal string, e.g. "0600".
func modeString(m os.FileMode) string {
	return fmt.Sprintf("%#o", uint32(m.Perm()))
}
