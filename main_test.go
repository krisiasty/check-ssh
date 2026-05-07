package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"reflect"
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
	ruleCiphers.check(config{"ciphers": "   "}, &res)
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
			params:  params{host: "example.com", generate: "99-ssh-hardened.conf"},
			wantErr: true,
		},
		{
			name:    "config and generate",
			params:  params{config: "sshd-T.txt", generate: "99-ssh-hardened.conf"},
			wantErr: true,
		},
		{
			name:    "path and generate",
			params:  params{pathSet: true, generate: "99-ssh-hardened.conf"},
			wantErr: true,
		},
		{
			name:    "port and generate",
			params:  params{portSet: true, generate: "99-ssh-hardened.conf"},
			wantErr: true,
		},
		{
			name:    "generate only",
			params:  params{generate: "99-ssh-hardened.conf"},
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
				"ciphers":       "aes256-gcm@openssh.com",
				"kexalgorithms": "curve25519-sha256",
			},
		},
		{
			name:  "CRLF line endings",
			input: "ciphers aes256-gcm@openssh.com\r\nmacs hmac-sha2-256\r\n",
			want: config{
				"ciphers": "aes256-gcm@openssh.com",
				"macs":    "hmac-sha2-256",
			},
		},
		{
			name:  "comments and blank lines skipped",
			input: "# header comment\n\nciphers aes256-gcm\n# inline\n\n",
			want:  config{"ciphers": "aes256-gcm"},
		},
		{
			name:  "key lowercased",
			input: "Ciphers aes256-gcm\nKexAlgorithms curve25519-sha256\n",
			want: config{
				"ciphers":       "aes256-gcm",
				"kexalgorithms": "curve25519-sha256",
			},
		},
		{
			name:  "key without value",
			input: "permitemptypasswords\n",
			want:  config{"permitemptypasswords": ""},
		},
		{
			name:  "empty input",
			input: "",
			want:  config{},
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
		binary.BigEndian.PutUint32(b[:4], uint32(len(s)))
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
