package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func resetCounters() {
	cntWarn = 0
	cntErr = 0
	cntMissing = 0
}

func TestRuleCheckMissingSettingIsIncompleteConfig(t *testing.T) {
	resetCounters()
	ruleCiphers.check(config{})
	if cntMissing != 1 {
		t.Fatalf("missing setting should increment missing count, got %d", cntMissing)
	}

	resetCounters()
	ruleCiphers.check(config{"ciphers": "   "})
	if cntMissing != 1 {
		t.Fatalf("blank setting should increment missing count, got %d", cntMissing)
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
			params:  params{host: "example.com"},
			wantErr: false,
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
