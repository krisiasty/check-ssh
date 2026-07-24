//go:build unix

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEvalMode(t *testing.T) {
	// Masks mirror the config-file policy: group/other write is an error, read a warning.
	const (
		errMask  = 0o022
		warnMask = 0o044
	)
	tests := []struct {
		name string
		mode os.FileMode
		want permSeverity
	}{
		{"0600 is ok", 0o600, permOK},
		{"0400 stricter is ok", 0o400, permOK},
		{"0640 group read warns", 0o640, permWarn},
		{"0644 group+other read warns", 0o644, permWarn},
		{"0620 group write errors", 0o620, permError},
		{"0666 group+other write errors", 0o666, permError},
		{"0777 errors", 0o777, permError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := evalMode(tt.mode, errMask, warnMask); got != tt.want {
				t.Errorf("evalMode(%o) = %d, want %d", tt.mode, got, tt.want)
			}
		})
	}
}

func TestEvalModeSecretFile(t *testing.T) {
	// Private host key policy: any group/other access is an error, nothing is merely a warning.
	const errMask = 0o077
	if got := evalMode(0o600, errMask, 0); got != permOK {
		t.Errorf("evalMode(0600) = %d, want permOK", got)
	}
	if got := evalMode(0o640, errMask, 0); got != permError {
		t.Errorf("evalMode(0640) = %d, want permError (group read of a secret key)", got)
	}
}

func TestFixPermTargetTightensMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(path, []byte("x"), 0o666); err != nil { // #nosec G306 -- intentionally loose so the test can verify fixPermTarget tightens it
		t.Fatal(err)
	}
	tgt := permTarget{path: path, wantMode: 0o600, errorMask: 0o022, warnMask: 0o044}

	var res result
	checkPermTarget(tgt, true, &res)

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("mode after fix = %o, want 0600 (0666 &^ 0066)", got)
	}
}

func TestFixPermTargetPreservesStricterMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(path, []byte("x"), 0o400); err != nil {
		t.Fatal(err)
	}
	tgt := permTarget{path: path, wantMode: 0o600, errorMask: 0o022, warnMask: 0o044}

	fixPermTarget(tgt, mustStat(t, path))

	fi := mustStat(t, path)
	if got := fi.Mode().Perm(); got != 0o400 {
		t.Errorf("mode = %o, want 0400 preserved (fix must never loosen)", got)
	}
}

func TestCheckPermTargetMissingPathSkips(t *testing.T) {
	tgt := permTarget{path: filepath.Join(t.TempDir(), "absent"), wantMode: 0o600, errorMask: 0o022}
	var res result
	checkPermTarget(tgt, false, &res)
	if res.errors != 0 || res.warnings != 0 {
		t.Errorf("missing path should be skipped silently, got errors=%d warnings=%d", res.errors, res.warnings)
	}
}

func TestPermTargetsIncludesHostKeys(t *testing.T) {
	c := config{"hostkey": {"/etc/ssh/ssh_host_ed25519_key"}}
	targets := permTargets(c)

	var haveMain, havePriv, havePub bool
	for _, tt := range targets {
		switch tt.path {
		case sshdConfigPath:
			haveMain = true
		case "/etc/ssh/ssh_host_ed25519_key":
			havePriv = true
			if tt.errorMask != 0o077 {
				t.Errorf("private host key errorMask = %o, want 0077", tt.errorMask)
			}
		case "/etc/ssh/ssh_host_ed25519_key.pub":
			havePub = true
			if tt.errorMask != 0o022 {
				t.Errorf("public host key errorMask = %o, want 0022", tt.errorMask)
			}
		}
	}
	if !haveMain || !havePriv || !havePub {
		t.Errorf("permTargets missing entries: main=%v priv=%v pub=%v", haveMain, havePriv, havePub)
	}
}

func mustStat(t *testing.T, path string) os.FileInfo {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi
}
