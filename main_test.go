package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestRuleCheckMissingSettingIsIncompleteConfig(t *testing.T) {
	var res result
	ruleCiphers.check(config{}, &res)
	if res.missing != 1 {
		t.Fatalf("missing setting should increment missing count, got %d", res.missing)
	}

	res = result{}
	ruleCiphers.check(config{"ciphers": {"   "}}, &res)
	if res.missing != 1 {
		t.Fatalf("blank setting should increment missing count, got %d", res.missing)
	}
}

func TestValidateParamsRejectsInvalidModes(t *testing.T) {
	tests := []struct {
		name    string
		params  params
		wantErr bool
	}{
		{
			name:    "host and config",
			params:  params{host: "example.com", config: "sshd-T.txt"},
			wantErr: true,
		},
		{
			name:    "host and generate",
			params:  params{host: "example.com", generate: "00-ssh-hardened.conf"},
			wantErr: true,
		},
		{
			name:    "config and generate",
			params:  params{config: "sshd-T.txt", generate: "00-ssh-hardened.conf"},
			wantErr: true,
		},
		{
			name:    "path and generate",
			params:  params{pathSet: true, generate: "00-ssh-hardened.conf"},
			wantErr: true,
		},
		{
			name:    "port and generate",
			params:  params{portSet: true, generate: "00-ssh-hardened.conf"},
			wantErr: true,
		},
		{
			name:    "generate only",
			params:  params{generate: "00-ssh-hardened.conf"},
			wantErr: false,
		},
		{
			name:    "fix-perms and host",
			params:  params{fixPerms: true, host: "example.com", port: 22},
			wantErr: true,
		},
		{
			name:    "fix-perms and config",
			params:  params{fixPerms: true, config: "sshd-T.txt"},
			wantErr: true,
		},
		{
			name:    "fix-perms and generate",
			params:  params{fixPerms: true, generate: "00-ssh-hardened.conf"},
			wantErr: true,
		},
		{
			name:    "fix-perms only",
			params:  params{fixPerms: true},
			wantErr: false,
		},
		{
			name:    "host only",
			params:  params{host: "example.com", port: 22},
			wantErr: false,
		},
		{
			name:    "port out of range low",
			params:  params{host: "example.com", port: 0},
			wantErr: true,
		},
		{
			name:    "port out of range high",
			params:  params{host: "example.com", port: 70000},
			wantErr: true,
		},
		{
			name:    "port negative",
			params:  params{host: "example.com", port: -1},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateParams(tt.params)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateParams() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestReadSSHBanner(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("notice\r\nSSH-2.0-test\r\n"))
	got, err := readSSHBanner(r)
	if err != nil {
		t.Fatalf("readSSHBanner() error = %v", err)
	}
	if got != "SSH-2.0-test" {
		t.Fatalf("readSSHBanner() = %q", got)
	}
}

func TestReadSSHBannerRejectsLongLine(t *testing.T) {
	line := strings.Repeat("a", maxSSHBannerLineLen+1) + "\n"
	_, err := readSSHBanner(bufio.NewReader(strings.NewReader(line)))
	if err == nil {
		t.Fatal("readSSHBanner() should reject an overlong line")
	}
}

func TestReadSSHBannerRejectsTooManyPreBannerLines(t *testing.T) {
	input := strings.Repeat("notice\n", maxSSHBannerLines) + "SSH-2.0-test\r\n"
	_, err := readSSHBanner(bufio.NewReader(strings.NewReader(input)))
	if err == nil {
		t.Fatal("readSSHBanner() should reject too many pre-banner lines")
	}
}

func TestReadSSHPacketRejectsInvalidLengths(t *testing.T) {
	tests := []uint32{0, 4, maxSSHPacketLen + 1}
	for _, packetLen := range tests {
		t.Run("", func(t *testing.T) {
			var buf [4]byte
			binary.BigEndian.PutUint32(buf[:], packetLen)
			_, err := readSSHPacket(bufio.NewReader(bytes.NewReader(buf[:])))
			if err == nil {
				t.Fatalf("readSSHPacket() should reject packet length %d", packetLen)
			}
		})
	}
}

func TestReadSSHPacketRejectsInvalidPadding(t *testing.T) {
	var packet bytes.Buffer
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], 5)
	packet.Write(lenBuf[:])
	packet.Write([]byte{3, 0, 0, 0, 0})

	_, err := readSSHPacket(bufio.NewReader(&packet))
	if err == nil {
		t.Fatal("readSSHPacket() should reject padding shorter than 4 bytes")
	}
}

func TestLoadSshdConfigMissingFile(t *testing.T) {
	_, err := loadSshdConfig(filepath.Join(t.TempDir(), "nonexistent"))
	if err == nil {
		t.Fatal("loadSshdConfig() should fail for missing file")
	}
	ee, ok := errors.AsType[*exitError](err)
	if !ok || ee.code != fileReadError {
		t.Fatalf("expected exitError with code %d, got %v", fileReadError, err)
	}
}

func TestGetSshdConfigBadPath(t *testing.T) {
	_, err := getSshdConfig(filepath.Join(t.TempDir(), "nonexistent-sshd"))
	if err == nil {
		t.Fatal("getSshdConfig() should fail for missing binary")
	}
	ee, ok := errors.AsType[*exitError](err)
	if !ok || ee.code != sshdWrongPath {
		t.Fatalf("expected exitError with code %d, got %v", sshdWrongPath, err)
	}
}

func TestGenerateSnippet(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snippet.conf")
	if err := generateSnippet(path, false); err != nil {
		t.Fatalf("generateSnippet() error = %v", err)
	}
	got, err := loadSshdConfig(path)
	if err != nil {
		t.Fatalf("loadSshdConfig() error = %v", err)
	}
	if !strings.Contains(string(got), "Ciphers -") {
		t.Fatalf("snippet missing Ciphers directive:\n%s", got)
	}
	if !strings.Contains(string(got), "HostbasedAuthentication no") {
		t.Fatalf("snippet missing HostbasedAuthentication directive:\n%s", got)
	}
	if !strings.Contains(string(got), "Subsystem sftp internal-sftp") {
		t.Fatalf("snippet missing Subsystem directive:\n%s", got)
	}
	if !strings.Contains(string(got), "ClientAliveInterval 300") {
		t.Fatalf("snippet missing ClientAliveInterval directive:\n%s", got)
	}
	if !strings.Contains(string(got), "ClientAliveCountMax 0") {
		t.Fatalf("snippet missing ClientAliveCountMax directive:\n%s", got)
	}
	if !strings.Contains(string(got), "IgnoreRhosts yes") {
		t.Fatalf("snippet missing IgnoreRhosts directive:\n%s", got)
	}
	if !strings.Contains(string(got), "PermitRootLogin no") {
		t.Fatalf("snippet missing PermitRootLogin directive:\n%s", got)
	}
	if !strings.Contains(string(got), "PermitUserEnvironment no") {
		t.Fatalf("snippet missing PermitUserEnvironment directive:\n%s", got)
	}
	if !strings.Contains(string(got), "UsePAM yes") {
		t.Fatalf("snippet missing UsePAM directive:\n%s", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("os.Stat() error = %v", err)
	}
	if got := info.Mode().Perm(); got != cisConfigFileMode {
		t.Errorf("snippet mode = %o, want %o", got, cisConfigFileMode)
	}
}

func TestGenerateSnippetTightensExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snippet.conf")
	if err := os.WriteFile(path, []byte("stale\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := generateSnippet(path, false); err != nil {
		t.Fatalf("generateSnippet() error = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("os.Stat() error = %v", err)
	}
	if got := info.Mode().Perm(); got != cisConfigFileMode {
		t.Errorf("snippet mode = %o, want %o (regenerating should tighten permissions)", got, cisConfigFileMode)
	}
}

func TestGenerateSnippetUnwritable(t *testing.T) {
	err := generateSnippet(filepath.Join(t.TempDir(), "no-such-dir", "snippet.conf"), false)
	if err == nil {
		t.Fatal("generateSnippet() should fail when directory does not exist")
	}
	ee, ok := errors.AsType[*exitError](err)
	if !ok || ee.code != generateError {
		t.Fatalf("expected exitError with code %d, got %v", generateError, err)
	}
}

func TestValidateKEXINITPayload(t *testing.T) {
	if err := validateKEXINITPayload(nil); err == nil {
		t.Fatal("validateKEXINITPayload() should reject empty payloads")
	}
	if err := validateKEXINITPayload([]byte{1}); err == nil {
		t.Fatal("validateKEXINITPayload() should reject non-KEXINIT payloads")
	}
	if err := validateKEXINITPayload([]byte{20}); err != nil {
		t.Fatalf("validateKEXINITPayload() error = %v", err)
	}
}

func TestParseSshdConfig(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  config
	}{
		{
			name:  "basic key/value pairs",
			input: "ciphers aes256-gcm@openssh.com\nkexalgorithms curve25519-sha256\n",
			want: config{
				"ciphers":       {"aes256-gcm@openssh.com"},
				"kexalgorithms": {"curve25519-sha256"},
			},
		},
		{
			name:  "CRLF line endings",
			input: "ciphers aes256-gcm@openssh.com\r\nmacs hmac-sha2-256\r\n",
			want: config{
				"ciphers": {"aes256-gcm@openssh.com"},
				"macs":    {"hmac-sha2-256"},
			},
		},
		{
			name:  "comments and blank lines skipped",
			input: "# header comment\n\nciphers aes256-gcm\n# inline\n\n",
			want:  config{"ciphers": {"aes256-gcm"}},
		},
		{
			name:  "key lowercased",
			input: "Ciphers aes256-gcm\nKexAlgorithms curve25519-sha256\n",
			want: config{
				"ciphers":       {"aes256-gcm"},
				"kexalgorithms": {"curve25519-sha256"},
			},
		},
		{
			name:  "key without value",
			input: "permitemptypasswords\n",
			want:  config{"permitemptypasswords": {""}},
		},
		{
			name:  "empty input",
			input: "",
			want:  config{},
		},
		{
			name:  "repeated directive accumulates",
			input: "hostkey /etc/ssh/ssh_host_rsa_key\nhostkey /etc/ssh/ssh_host_ed25519_key\n",
			want: config{
				"hostkey": {"/etc/ssh/ssh_host_rsa_key", "/etc/ssh/ssh_host_ed25519_key"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseSshdConfig([]byte(tt.input))
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseSshdConfig() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseNameList(t *testing.T) {
	makeList := func(s string) []byte {
		b := make([]byte, 4+len(s))
		binary.BigEndian.PutUint32(b[:4], uint32(len(s))) // #nosec G115 -- test input is a short literal string
		copy(b[4:], s)
		return b
	}

	t.Run("basic value", func(t *testing.T) {
		data := makeList("aes256-gcm,chacha20-poly1305")
		got, off, err := parseNameList(data, 0)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if got != "aes256-gcm,chacha20-poly1305" {
			t.Errorf("value = %q", got)
		}
		if off != len(data) {
			t.Errorf("offset = %d, want %d", off, len(data))
		}
	})

	t.Run("zero-length list", func(t *testing.T) {
		got, off, err := parseNameList(makeList(""), 0)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if got != "" || off != 4 {
			t.Errorf("value = %q, offset = %d", got, off)
		}
	})

	t.Run("buffer too short for length prefix", func(t *testing.T) {
		if _, _, err := parseNameList([]byte{0, 0, 0}, 0); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("declared length exceeds buffer", func(t *testing.T) {
		data := []byte{0, 0, 0, 10, 'a', 'b', 'c', 'd'}
		if _, _, err := parseNameList(data, 0); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("respects starting offset", func(t *testing.T) {
		data := append([]byte{0xFF, 0xFF}, makeList("hello")...)
		got, off, err := parseNameList(data, 2)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if got != "hello" || off != len(data) {
			t.Errorf("value = %q, offset = %d", got, off)
		}
	})
}

func TestFilterKexExtensions(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"only extensions", "ext-info-s,kex-strict-s-v00@openssh.com", ""},
		{"only real algos", "curve25519-sha256,ecdh-sha2-nistp384", "curve25519-sha256,ecdh-sha2-nistp384"},
		{"mixed strips extensions", "curve25519-sha256,ext-info-s,ecdh-sha2-nistp384,kex-strict-s-v00@openssh.com", "curve25519-sha256,ecdh-sha2-nistp384"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := filterKexExtensions(tt.in); got != tt.want {
				t.Errorf("filterKexExtensions(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestMergeAlgos(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want string
	}{
		{"both empty", "", "", ""},
		{"a empty", "", "x,y", "x,y"},
		{"b empty", "x,y", "", "x,y"},
		{"identical lists dedupe", "x,y", "x,y", "x,y"},
		{"disjoint lists union", "a,b", "c,d", "a,b,c,d"},
		{"partial overlap preserves first-appearance order", "a,b,c", "b,c,d", "a,b,c,d"},
		{"order from second list when only there", "y,x", "z,y", "y,x,z"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mergeAlgos(tt.a, tt.b); got != tt.want {
				t.Errorf("mergeAlgos(%q, %q) = %q, want %q", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestSplitAlgos(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"single", "aes256", []string{"aes256"}},
		{"multiple", "a,b,c", []string{"a", "b", "c"}},
		{"strips spaces", " a , b , c ", []string{"a", "b", "c"}},
		{"drops empty entries", "a,,b,", []string{"a", "b"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := splitAlgos(tt.in); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("splitAlgos(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestVerify(t *testing.T) {
	r := rule{
		option:         "Test",
		recommended:    "good1,good2",
		notRecommended: "meh",
		prohibited:     "bad",
	}.build()

	tests := []struct {
		name              string
		enabled           string
		wantWarn, wantErr int
	}{
		{"all recommended", "good1,good2", 0, 0},
		{"not recommended", "meh", 1, 0},
		{"prohibited", "bad", 0, 1},
		{"unknown is warning", "weird", 1, 0},
		{"mixed", "good1,meh,bad,weird", 2, 1},
		{"empty input", "", 0, 0},
		{"spaces stripped", " good1 , meh ", 1, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var res result
			verify(r, tt.enabled, &res)
			if res.warnings != tt.wantWarn || res.errors != tt.wantErr {
				t.Errorf("warnings=%d errors=%d, want warnings=%d errors=%d",
					res.warnings, res.errors, tt.wantWarn, tt.wantErr)
			}
			if res.missing != 0 {
				t.Errorf("verify should not touch missing, got %d", res.missing)
			}
		})
	}
}

func TestRuleBuild(t *testing.T) {
	r := rule{
		recommended:    "a, b",
		notRecommended: "c",
		prohibited:     "d,e,f",
	}.build()
	if !reflect.DeepEqual(r.recList, []string{"a", "b"}) {
		t.Errorf("recList = %v", r.recList)
	}
	if !reflect.DeepEqual(r.nrList, []string{"c"}) {
		t.Errorf("nrList = %v", r.nrList)
	}
	if !reflect.DeepEqual(r.prList, []string{"d", "e", "f"}) {
		t.Errorf("prList = %v", r.prList)
	}

	empty := rule{}.build()
	if empty.recList != nil || empty.nrList != nil || empty.prList != nil {
		t.Errorf("empty rule should produce nil lists, got %v %v %v", empty.recList, empty.nrList, empty.prList)
	}
}

func TestRuleConfigLine(t *testing.T) {
	boolRule := rule{
		option:      "HostbasedAuthentication",
		recommended: "no",
		prohibited:  "yes",
		boolean:     true,
	}.build()

	algoRule := rule{
		option:         "Ciphers",
		recommended:    "good",
		notRecommended: "meh1,meh2",
		prohibited:     "bad1,bad2",
	}.build()

	noProhibitedRule := rule{
		option:      "Foo",
		recommended: "good",
	}.build()

	tests := []struct {
		name   string
		rule   rule
		strict bool
		want   string
	}{
		{"boolean emits positive directive", boolRule, false, "HostbasedAuthentication no"},
		{"boolean ignores strict flag", boolRule, true, "HostbasedAuthentication no"},
		{"non-strict removes only prohibited", algoRule, false, "Ciphers -bad1,bad2"},
		{"strict adds notRecommended", algoRule, true, "Ciphers -bad1,bad2,meh1,meh2"},
		{"empty prohibited returns empty", noProhibitedRule, false, ""},
		{"empty even in strict if nothing to remove", noProhibitedRule, true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.rule.configLine(tt.strict); got != tt.want {
				t.Errorf("configLine() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestInjectGenerateDefault(t *testing.T) {
	saved := os.Args
	t.Cleanup(func() { os.Args = saved })

	tests := []struct {
		name string
		argv []string
		want []string
	}{
		{
			name: "no -generate flag",
			argv: []string{"prog", "-config", "foo"},
			want: []string{"prog", "-config", "foo"},
		},
		{
			name: "-generate alone gets default",
			argv: []string{"prog", "-generate"},
			want: []string{"prog", "-generate", "default.conf"},
		},
		{
			name: "--generate variant",
			argv: []string{"prog", "--generate"},
			want: []string{"prog", "--generate", "default.conf"},
		},
		{
			name: "explicit value preserved",
			argv: []string{"prog", "-generate", "myfile"},
			want: []string{"prog", "-generate", "myfile"},
		},
		{
			name: "default injected before next flag",
			argv: []string{"prog", "-generate", "-strict"},
			want: []string{"prog", "-generate", "default.conf", "-strict"},
		},
		{
			name: "-generate=value form is left alone",
			argv: []string{"prog", "-generate=foo"},
			want: []string{"prog", "-generate=foo"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Args = append([]string(nil), tt.argv...)
			injectGenerateDefault("default.conf")
			if !reflect.DeepEqual(os.Args, tt.want) {
				t.Errorf("os.Args = %v, want %v", os.Args, tt.want)
			}
		})
	}
}

func TestMpintBits(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want int
	}{
		{"empty", nil, 0},
		{"canonical zero (single 0x00)", []byte{0x00}, 0},
		{"value 1", []byte{0x01}, 1},
		{"value 0xff", []byte{0xff}, 8},
		{"value 0x100", []byte{0x01, 0x00}, 9},
		{"sign-padded 0x80", []byte{0x00, 0x80}, 8},
		{"two bytes 0xffff", []byte{0xff, 0xff}, 16},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mpintBits(tt.in); got != tt.want {
				t.Errorf("mpintBits(%x) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

// writeSSHString writes an SSH wire-format length-prefixed string into buf.
func writeSSHString(buf *bytes.Buffer, s []byte) {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(s))) // #nosec G115 -- test inputs are small literals
	buf.Write(hdr[:])
	buf.Write(s)
}

// pubKeyFile constructs an OpenSSH-format `.pub` file from a wire blob.
func writePubKeyFile(t *testing.T, algo string, blob []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ssh_host_test_key.pub")
	encoded := base64.StdEncoding.EncodeToString(blob)
	if err := os.WriteFile(path, []byte(algo+" "+encoded+" test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadHostKeyPubEd25519(t *testing.T) {
	var blob bytes.Buffer
	writeSSHString(&blob, []byte("ssh-ed25519"))
	writeSSHString(&blob, make([]byte, 32))

	path := writePubKeyFile(t, "ssh-ed25519", blob.Bytes())
	algo, bitLen, err := readHostKeyPub(path)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if algo != "ssh-ed25519" || bitLen != 256 {
		t.Errorf("got (%q, %d), want (ssh-ed25519, 256)", algo, bitLen)
	}
}

func TestReadHostKeyPubECDSA(t *testing.T) {
	var blob bytes.Buffer
	writeSSHString(&blob, []byte("ecdsa-sha2-nistp384"))
	writeSSHString(&blob, []byte("nistp384"))
	writeSSHString(&blob, make([]byte, 97)) // uncompressed P-384 point

	path := writePubKeyFile(t, "ecdsa-sha2-nistp384", blob.Bytes())
	algo, bitLen, err := readHostKeyPub(path)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if algo != "ecdsa-sha2-nistp384" || bitLen != 384 {
		t.Errorf("got (%q, %d), want (ecdsa-sha2-nistp384, 384)", algo, bitLen)
	}
}

func TestReadHostKeyPubRSA2048(t *testing.T) {
	var blob bytes.Buffer
	writeSSHString(&blob, []byte("ssh-rsa"))
	writeSSHString(&blob, []byte{0x01, 0x00, 0x01}) // e = 65537
	// 2048-bit modulus: sign byte 0x00 + 0xff high byte + 255 trailing bytes
	n := make([]byte, 257)
	n[1] = 0xff
	writeSSHString(&blob, n)

	path := writePubKeyFile(t, "ssh-rsa", blob.Bytes())
	algo, bitLen, err := readHostKeyPub(path)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if algo != "ssh-rsa" || bitLen != 2048 {
		t.Errorf("got (%q, %d), want (ssh-rsa, 2048)", algo, bitLen)
	}
}

func TestReadHostKeyPubMissingFile(t *testing.T) {
	if _, _, err := readHostKeyPub(filepath.Join(t.TempDir(), "nope.pub")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestReadHostKeyPubMalformed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.pub")
	if err := os.WriteFile(path, []byte("only-one-field\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readHostKeyPub(path); err == nil {
		t.Fatal("expected error for malformed file")
	}
}

func TestCheckHostKeySizes(t *testing.T) {
	makeRSA := func(t *testing.T, dir, name string, modulusBytes int) {
		t.Helper()
		var blob bytes.Buffer
		writeSSHString(&blob, []byte("ssh-rsa"))
		writeSSHString(&blob, []byte{0x01, 0x00, 0x01})
		n := make([]byte, modulusBytes+1) // +1 for sign byte
		n[1] = 0xff                       // exact modulusBytes*8 bits
		writeSSHString(&blob, n)
		path := filepath.Join(dir, name+".pub")
		encoded := base64.StdEncoding.EncodeToString(blob.Bytes())
		if err := os.WriteFile(path, []byte("ssh-rsa "+encoded+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	makeEd25519 := func(t *testing.T, dir, name string) {
		t.Helper()
		var blob bytes.Buffer
		writeSSHString(&blob, []byte("ssh-ed25519"))
		writeSSHString(&blob, make([]byte, 32))
		path := filepath.Join(dir, name+".pub")
		encoded := base64.StdEncoding.EncodeToString(blob.Bytes())
		if err := os.WriteFile(path, []byte("ssh-ed25519 "+encoded+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("4096-bit RSA passes silently", func(t *testing.T) {
		dir := t.TempDir()
		makeRSA(t, dir, "ssh_host_rsa_key", 512) // 4096 bits
		c := config{"hostkey": {filepath.Join(dir, "ssh_host_rsa_key")}}
		var res result
		checkHostKeySizes(c, &res)
		if res.errors != 0 || res.warnings != 0 {
			t.Errorf("got errors=%d warnings=%d, want 0/0", res.errors, res.warnings)
		}
	})

	t.Run("3072-bit RSA passes silently", func(t *testing.T) {
		dir := t.TempDir()
		makeRSA(t, dir, "ssh_host_rsa_key", 384) // 3072 bits
		c := config{"hostkey": {filepath.Join(dir, "ssh_host_rsa_key")}}
		var res result
		checkHostKeySizes(c, &res)
		if res.errors != 0 || res.warnings != 0 {
			t.Errorf("got errors=%d warnings=%d, want 0/0", res.errors, res.warnings)
		}
	})

	t.Run("2048-bit RSA warns", func(t *testing.T) {
		dir := t.TempDir()
		makeRSA(t, dir, "ssh_host_rsa_key", 256) // 2048 bits
		c := config{"hostkey": {filepath.Join(dir, "ssh_host_rsa_key")}}
		var res result
		checkHostKeySizes(c, &res)
		if res.warnings != 1 || res.errors != 0 {
			t.Errorf("got errors=%d warnings=%d, want 0/1", res.errors, res.warnings)
		}
	})

	t.Run("1024-bit RSA errors", func(t *testing.T) {
		dir := t.TempDir()
		makeRSA(t, dir, "ssh_host_rsa_key", 128) // 1024 bits
		c := config{"hostkey": {filepath.Join(dir, "ssh_host_rsa_key")}}
		var res result
		checkHostKeySizes(c, &res)
		if res.errors != 1 {
			t.Errorf("got errors=%d, want 1", res.errors)
		}
	})

	t.Run("Ed25519 ignored by size check", func(t *testing.T) {
		dir := t.TempDir()
		makeEd25519(t, dir, "ssh_host_ed25519_key")
		c := config{"hostkey": {filepath.Join(dir, "ssh_host_ed25519_key")}}
		var res result
		checkHostKeySizes(c, &res)
		if res.errors != 0 || res.warnings != 0 {
			t.Errorf("got errors=%d warnings=%d, want 0/0", res.errors, res.warnings)
		}
	})

	t.Run("missing pub file warns", func(t *testing.T) {
		c := config{"hostkey": {filepath.Join(t.TempDir(), "missing")}}
		var res result
		checkHostKeySizes(c, &res)
		if res.warnings != 1 {
			t.Errorf("got warnings=%d, want 1", res.warnings)
		}
	})

	t.Run("no hostkey directives warns", func(t *testing.T) {
		var res result
		checkHostKeySizes(config{}, &res)
		if res.warnings != 1 {
			t.Errorf("got warnings=%d, want 1", res.warnings)
		}
	})

	t.Run("multiple hostkeys all checked", func(t *testing.T) {
		dir := t.TempDir()
		makeRSA(t, dir, "ssh_host_rsa_key", 256)    // 2048 — warn
		makeEd25519(t, dir, "ssh_host_ed25519_key") // ignored
		c := config{"hostkey": {
			filepath.Join(dir, "ssh_host_rsa_key"),
			filepath.Join(dir, "ssh_host_ed25519_key"),
		}}
		var res result
		checkHostKeySizes(c, &res)
		if res.warnings != 1 || res.errors != 0 {
			t.Errorf("got errors=%d warnings=%d, want 0/1", res.errors, res.warnings)
		}
	})
}

func TestCheckSFTPSubsystem(t *testing.T) {
	tests := []struct {
		name     string
		config   config
		warnings int
	}{
		{"internal-sftp is recommended", config{"subsystem": {"sftp internal-sftp"}}, 0},
		{"internal-sftp with args is recommended", config{"subsystem": {"sftp internal-sftp -f AUTH -l INFO"}}, 0},
		{"external sftp-server warns", config{"subsystem": {"sftp /usr/lib/openssh/sftp-server"}}, 1},
		{"absent sftp subsystem warns", config{}, 1},
		{"other subsystem without sftp warns", config{"subsystem": {"foo /usr/bin/foo"}}, 1},
		{"case-insensitive subsystem name", config{"subsystem": {"SFTP internal-sftp"}}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var res result
			checkSFTPSubsystem(tt.config, &res)
			if res.warnings != tt.warnings || res.errors != 0 {
				t.Errorf("got errors=%d warnings=%d, want errors=0 warnings=%d", res.errors, res.warnings, tt.warnings)
			}
		})
	}
}

func TestCheckRecommendedValue(t *testing.T) {
	interval := func(got string) bool {
		n, err := strconv.Atoi(got)
		return err == nil && n >= 1 && n <= 300
	}
	exactZero := func(got string) bool { return got == "0" }
	tests := []struct {
		name     string
		config   config
		option   string
		accept   func(string) bool
		warnings int
	}{
		{"interval 300 is recommended", config{"clientaliveinterval": {"300"}}, "ClientAliveInterval", interval, 0},
		{"interval stricter non-zero is recommended", config{"clientaliveinterval": {"60"}}, "ClientAliveInterval", interval, 0},
		{"interval 0 warns", config{"clientaliveinterval": {"0"}}, "ClientAliveInterval", interval, 1},
		{"interval above 300 warns", config{"clientaliveinterval": {"600"}}, "ClientAliveInterval", interval, 1},
		{"interval non-numeric warns", config{"clientaliveinterval": {"abc"}}, "ClientAliveInterval", interval, 1},
		{"interval absent warns", config{}, "ClientAliveInterval", interval, 1},
		{"countmax 0 is recommended", config{"clientalivecountmax": {"0"}}, "ClientAliveCountMax", exactZero, 0},
		{"countmax nonzero warns", config{"clientalivecountmax": {"3"}}, "ClientAliveCountMax", exactZero, 1},
		{"ignorerhosts yes is recommended", config{"ignorerhosts": {"yes"}}, "IgnoreRhosts", func(got string) bool { return got == "yes" }, 0},
		{"ignorerhosts no warns", config{"ignorerhosts": {"no"}}, "IgnoreRhosts", func(got string) bool { return got == "yes" }, 1},
		{"ignorerhosts absent warns", config{}, "IgnoreRhosts", func(got string) bool { return got == "yes" }, 1},
		{"permitrootlogin no is recommended", config{"permitrootlogin": {"no"}}, "PermitRootLogin", func(got string) bool { return got == "no" }, 0},
		{"permitrootlogin prohibit-password warns", config{"permitrootlogin": {"prohibit-password"}}, "PermitRootLogin", func(got string) bool { return got == "no" }, 1},
		{"permitrootlogin absent warns", config{}, "PermitRootLogin", func(got string) bool { return got == "no" }, 1},
		{"permituserenvironment no is recommended", config{"permituserenvironment": {"no"}}, "PermitUserEnvironment", func(got string) bool { return got == "no" }, 0},
		{"permituserenvironment yes warns", config{"permituserenvironment": {"yes"}}, "PermitUserEnvironment", func(got string) bool { return got == "no" }, 1},
		{"permituserenvironment absent warns", config{}, "PermitUserEnvironment", func(got string) bool { return got == "no" }, 1},
		{"usepam yes is recommended", config{"usepam": {"yes"}}, "UsePAM", func(got string) bool { return got == "yes" }, 0},
		{"usepam no warns", config{"usepam": {"no"}}, "UsePAM", func(got string) bool { return got == "yes" }, 1},
		{"usepam absent warns", config{}, "UsePAM", func(got string) bool { return got == "yes" }, 1},
		{"whitespace is trimmed", config{"clientaliveinterval": {"  60  "}}, "ClientAliveInterval", interval, 0},
		{"last value wins", config{"clientaliveinterval": {"0", "120"}}, "ClientAliveInterval", interval, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var res result
			checkRecommendedValue(tt.config, tt.option, "n/a", tt.accept, &res)
			if res.warnings != tt.warnings || res.errors != 0 {
				t.Errorf("got errors=%d warnings=%d, want errors=0 warnings=%d", res.errors, res.warnings, tt.warnings)
			}
		})
	}
}
