package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/lmittmann/tint"
	"github.com/mattn/go-isatty"
)

// build info, overwritten by goreleaser
var (
	version = "dev (unreleased)"
	commit  = "none"
	date    = "unknown"
)

// global counters
var (
	cntWarn = 0 // total number of warnings
	cntErr  = 0 // total number of errors
)

type params struct {
	path     string
	config   string
	host     string
	port     int
	generate string // non-empty: generate snippet to this path
	strict   bool
	version  bool
	debug    bool
	help     bool
}

type config map[string]string

// injectGenerateDefault inserts a default filename into os.Args when -generate is
// present but not followed by a value, so flag.StringVar can consume it normally.
func injectGenerateDefault(def string) {
	for i, arg := range os.Args[1:] {
		if arg == "-generate" || arg == "--generate" {
			next := i + 2 // position of the element after -generate in os.Args
			if next >= len(os.Args) || strings.HasPrefix(os.Args[next], "-") {
				args := make([]string, len(os.Args)+1)
				copy(args, os.Args[:next])
				args[next] = def
				copy(args[next+1:], os.Args[next:])
				os.Args = args
			}
			break
		}
	}
}

// application return codes
const (
	noError         = iota // 0
	checkUserError         // 1
	isRootError            // 2
	sshdWrongPath          // 3
	sshdExecError          // 4
	fileReadError          // 5
	remoteConnError        // 6
	generateError          // 7
	checkFailed     = 99   // 99
)

// rule holds the security best practices classification for a single sshd_config option
type rule struct {
	option         string
	recommended    string
	notRecommended string
	prohibited     string
	boolean        bool // if true, configLine emits a positive directive (not a denylist)
}

func (r rule) check(c config) {
	verify(r.option, c[strings.ToLower(r.option)], r.recommended, r.notRecommended, r.prohibited)
}

// configLine returns the sshd_config directive that removes disallowed values from the default set.
// Boolean options emit a positive directive. For algorithm lists, prohibited values are always removed;
// in strict mode not-recommended values are removed too.
func (r rule) configLine(strict bool) string {
	if r.boolean {
		return r.option + " " + r.recommended
	}
	var remove []string
	for algo := range strings.SplitSeq(r.prohibited, ",") {
		if algo != "" {
			remove = append(remove, algo)
		}
	}
	if strict {
		for algo := range strings.SplitSeq(r.notRecommended, ",") {
			if algo != "" {
				remove = append(remove, algo)
			}
		}
	}
	return r.option + " -" + strings.Join(remove, ",")
}

var (
	ruleCASignatureAlgorithms = rule{
		option: "CASignatureAlgorithms",
		recommended: "ecdsa-sha2-nistp384,rsa-sha2-512,ecdsa-sha2-nistp521," +
			"ssh-ed25519,sk-ecdsa-sha2-nistp256@openssh.com,sk-ssh-ed25519@openssh.com",
		notRecommended: "rsa-sha2-256,ecdsa-sha2-nistp256",
		prohibited:     "ssh-rsa,ssh-dss",
	}
	ruleCiphers = rule{
		option:         "Ciphers",
		recommended:    "aes256-gcm@openssh.com,chacha20-poly1305@openssh.com",
		notRecommended: "aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr",
		prohibited:     "aes256-cbc,aes192-cbc,aes128-cbc,3des-cbc,arcfour,arcfour128,arcfour256,blowfish-cbc,cast128-cbc",
	}
	ruleHostbasedAcceptedAlgorithms = rule{
		option: "HostbasedAcceptedAlgorithms",
		recommended: "ecdsa-sha2-nistp384,ecdsa-sha2-nistp384-cert-v01@openssh.com,rsa-sha2-512," +
			"rsa-sha2-512-cert-v01@openssh.com,ecdsa-sha2-nistp521,ecdsa-sha2-nistp521-cert-v01@openssh.com," +
			"ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com," +
			"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com",
		notRecommended: "rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com,ecdsa-sha2-nistp256," +
			"ecdsa-sha2-nistp256-cert-v01@openssh.com",
		prohibited: "ssh-rsa,ssh-rsa-cert-v01@openssh.com,ssh-dss,ssh-dss-cert-v01@openssh.com",
	}
	ruleHostbasedAuthentication = rule{
		option:         "HostbasedAuthentication",
		recommended:    "no",
		notRecommended: "",
		prohibited:     "yes",
		boolean:        true,
	}
	ruleHostKeyAlgorithms = rule{
		option: "HostKeyAlgorithms",
		recommended: "ecdsa-sha2-nistp384,ecdsa-sha2-nistp384-cert-v01@openssh.com,rsa-sha2-512," +
			"rsa-sha2-512-cert-v01@openssh.com,ecdsa-sha2-nistp521,ecdsa-sha2-nistp521-cert-v01@openssh.com," +
			"ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com," +
			"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com",
		notRecommended: "rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com,ecdsa-sha2-nistp256," +
			"ecdsa-sha2-nistp256-cert-v01@openssh.com",
		prohibited: "ssh-rsa,ssh-rsa-cert-v01@openssh.com,ssh-dss,ssh-dss-cert-v01@openssh.com",
	}
	ruleKexAlgorithms = rule{
		option: "KexAlgorithms",
		recommended: "ecdh-sha2-nistp384,ecdh-sha2-nistp521,curve25519-sha256,curve25519-sha256@libssh.org," +
			"sntrup761x25519-sha512@openssh.com,sntrup761x25519-sha512,mlkem768x25519-sha256",
		notRecommended: "ecdh-sha2-nistp256,sntrup4591761x25519-sha512@tinyssh.org," +
			"diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256",
		prohibited: "diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group14-sha256," +
			"diffie-hellman-group-exchange-sha1",
	}
	ruleMACs = rule{
		option:         "MACs",
		recommended:    "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com",
		notRecommended: "hmac-sha2-256,hmac-sha2-512,umac-128@openssh.com,umac-128-etm@openssh.com",
		prohibited: "hmac-md5,hmac-md5-96,hmac-md5-etm@openssh.com,hmac-md5-96-etm@openssh.com,hmac-sha1," +
			"hmac-sha1-96,hmac-sha1-etm@openssh.com,hmac-sha1-96-etm@openssh.com,umac-64@openssh.com," +
			"umac-64-etm@openssh.com",
	}
	rulePubkeyAcceptedAlgorithms = rule{
		option: "PubkeyAcceptedAlgorithms",
		recommended: "ecdsa-sha2-nistp384,ecdsa-sha2-nistp384-cert-v01@openssh.com,rsa-sha2-512," +
			"rsa-sha2-512-cert-v01@openssh.com,ecdsa-sha2-nistp521,ecdsa-sha2-nistp521-cert-v01@openssh.com," +
			"ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com," +
			"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com",
		notRecommended: "rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com,ecdsa-sha2-nistp256," +
			"ecdsa-sha2-nistp256-cert-v01@openssh.com",
		prohibited: "ssh-rsa,ssh-rsa-cert-v01@openssh.com,ssh-dss,ssh-dss-cert-v01@openssh.com",
	}

	// localRules is the ordered list of rules applied in local mode and used for snippet generation
	localRules = []rule{
		ruleCASignatureAlgorithms,
		ruleCiphers,
		ruleHostbasedAcceptedAlgorithms,
		ruleHostbasedAuthentication,
		ruleHostKeyAlgorithms,
		ruleKexAlgorithms,
		ruleMACs,
		rulePubkeyAcceptedAlgorithms,
	}
)

func getParams() params {
	prog := filepath.Base(os.Args[0])

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "\n%s checks if sshd configuration conforms to security best practices\n\n", prog)
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", prog)
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nProgram must be executed as root user (or via sudo) to be able to access local sshd configuration\n")
	}

	var c params

	injectGenerateDefault("99-ssh-hardened.conf")
	flag.StringVar(&c.path, "path", "/usr/sbin/sshd", "full path to sshd binary")
	flag.StringVar(&c.config, "config", "", "full path to the output of 'sshd -T' command")
	flag.StringVar(&c.host, "host", "", "remote host to scan via SSH handshake")
	flag.IntVar(&c.port, "port", 22, "remote SSH port")
	flag.StringVar(&c.generate, "generate", "", `generate sshd_config.d snippet; optional filename (default "99-ssh-hardened.conf")`)
	flag.BoolVar(&c.strict, "strict", false, "strict check: fail on warnings")
	flag.BoolVar(&c.version, "version", false, "print program version and quit")
	flag.BoolVar(&c.debug, "debug", false, "increase logging level")
	flag.BoolVar(&c.help, "help", false, "print help and exit")
	flag.Parse()

	if c.version {
		fmt.Printf("%s version: %s (commit: %s, build date: %s)\n", prog, version, commit, date)
		os.Exit(noError)
	}

	if c.help {
		flag.Usage()
		os.Exit(noError)
	}

	return c
}

func initLog(debug bool) {
	var loglevel = slog.LevelInfo
	if debug {
		loglevel = slog.LevelDebug
	}
	slog.SetDefault(slog.New(
		tint.NewHandler(os.Stderr, &tint.Options{
			Level:      loglevel,
			TimeFormat: time.StampMilli,
			NoColor:    !isatty.IsTerminal(os.Stderr.Fd()),
		}),
	))
	slog.Debug(fmt.Sprintf("log level: %v", loglevel))
}

func ensureExecutedAsRoot() {
	slog.Debug("enrusing program is running as root user")
	u, err := user.Current()
	if err != nil {
		slog.Error("unable to get current user", "err", err.Error())
		os.Exit(checkUserError)
	}
	if u.Username != "root" {
		slog.Error("program must be executed by root", "current_user", u.Username)
		os.Exit(isRootError)
	}
}

// return parsed sshd config as a map
func parseSshdConfig(buf []byte) config {
	slog.Debug("parsing sshd config")
	c := make(config)
	for line := range strings.SplitSeq(string(buf), "\n") {
		kv := strings.SplitN(line, " ", 2)
		if len(kv) < 2 {
			c[kv[0]] = ""
		} else {
			c[kv[0]] = kv[1]
		}
	}
	return c
}

// execute sshd -T, grab output and return parsed config as a map
func getSshdConfig(path string) []byte {
	slog.Debug("getting config from 'sshd -T' command", "path", path)
	p, err := exec.LookPath(path)
	if err != nil {
		slog.Error("cannot locate sshd binary", "err", err.Error())
		os.Exit(sshdWrongPath)
	}
	slog.Debug("sshd binary", "path", p)
	buf, err := exec.CommandContext(context.Background(), p, "-T").Output() // #nosec G204 -- sshd path is an explicit CLI input for this admin tool.
	if err != nil {
		slog.Error("error executing sshd -T", "path", p, "err", err.Error())
		os.Exit(sshdExecError)
	}
	return buf
}

// load sshd config from file, parse it and return as a map
// the file must contain an output from 'sshd -T' command
func loadSshdConfig(file string) []byte {
	slog.Debug("getting sshd config from specified file", "file", file)
	buf, err := os.ReadFile(file) // #nosec G304 -- config file path is an explicit CLI input for offline checks.
	if err != nil {
		slog.Error("cannot load specified file", "err", err.Error())
		os.Exit(fileReadError)
	}
	return buf
}

// verify if enabled options match recommended, not recommended or prohibited lists
func verify(option string, enabled string, recommended string, notRecommended string, prohibited string) {
	slog.Info("verifying", "option", option)
	slog.Debug("enabled values", "option", option, "values", enabled)
	slog.Debug("recommended values", "option", option, "values", recommended)
	slog.Debug("not recommended values", "option", option, "values", notRecommended)
	slog.Debug("prohibited values", "option", option, "values", prohibited)
	// remove spaces and split on comma separator
	en := strings.Split(strings.ReplaceAll(enabled, " ", ""), ",")
	re := strings.Split(strings.ReplaceAll(recommended, " ", ""), ",")
	nr := strings.Split(strings.ReplaceAll(notRecommended, " ", ""), ",")
	pr := strings.Split(strings.ReplaceAll(prohibited, " ", ""), ",")
	for _, v := range en {
		if v == "" {
			continue
		}
		switch {
		case slices.Contains(re, v):
			slog.Info("found recommended setting", "option", option, "value", v)
		case slices.Contains(nr, v):
			slog.Warn("found not recommended setting", "option", option, "value", v)
			cntWarn++
		case slices.Contains(pr, v):
			slog.Error("found prohibited setting", "option", option, "value", v)
			cntErr++
		default:
			slog.Warn("found unknown setting", "option", option, "value", v)
			cntWarn++
		}
	}
}

// verify CASignatureAlgorithms
// https://man.openbsd.org/sshd_config#CASignatureAlgorithms
func CASignatureAlgorithms(c config) { ruleCASignatureAlgorithms.check(c) }

// verify Ciphers
// https://man.openbsd.org/sshd_config#Ciphers
func Ciphers(c config) { ruleCiphers.check(c) }

// verify HostbasedAcceptedAlgorithms (former: HostbasedAcceptedKeyTypes)
// https://man.openbsd.org/sshd_config#HostbasedAcceptedAlgorithms
func HostbasedAcceptedAlgorithms(c config) { ruleHostbasedAcceptedAlgorithms.check(c) }

// verify HostbasedAuthentication
// https://man.openbsd.org/sshd_config#HostbasedAuthentication
func HostbasedAuthentication(c config) { ruleHostbasedAuthentication.check(c) }

// verify HostKeyAlgorithms
// https://man.openbsd.org/sshd_config#HostKeyAlgorithms
func HostKeyAlgorithms(c config) { ruleHostKeyAlgorithms.check(c) }

// verify KexAlgorithms
// https://man.openbsd.org/sshd_config#KexAlgorithms
func KexAlgorithms(c config) { ruleKexAlgorithms.check(c) }

// verify MACs
// https://man.openbsd.org/sshd_config#MACs
func MACs(c config) { ruleMACs.check(c) }

// verify PubkeyAcceptedAlgorithms (former: PubkeyAcceptedKeyTypes)
// https://man.openbsd.org/sshd_config#PubkeyAcceptedAlgorithms
func PubkeyAcceptedAlgorithms(c config) { rulePubkeyAcceptedAlgorithms.check(c) }

// generateSnippet writes an sshd_config.d snippet that restricts each option to recommended values.
// In strict mode only recommended values are included; otherwise not-recommended are included too.
func generateSnippet(path string, strict bool) {
	slog.Info("generating sshd_config.d snippet", "path", path, "strict", strict)
	var sb strings.Builder
	fmt.Fprintf(&sb, "# Generated by check-ssh %s (commit: %s)\n", version, commit)
	fmt.Fprintf(&sb, "# strict: %v\n", strict)
	for _, r := range localRules {
		fmt.Fprintln(&sb, r.configLine(strict))
	}
	if err := os.WriteFile(path, []byte(sb.String()), 0o644); err != nil { // #nosec G306 -- config snippet is not a secret
		slog.Error("cannot write snippet", "path", path, "err", err.Error())
		os.Exit(generateError)
	}
	slog.Info("snippet written", "path", path)
	if strings.HasPrefix(filepath.Clean(path), "/etc/") {
		u, err := user.Current()
		if err == nil && u.Username != "root" {
			slog.Warn("snippet written as non-root; sshd will ignore it — run: sudo chown root:root " + path)
		}
	}
}

// readSSHBanner reads lines from r until it finds the server's SSH identification string
func readSSHBanner(r *bufio.Reader) (string, error) {
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("reading SSH banner: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(line, "SSH-") {
			return line, nil
		}
	}
}

// readSSHPacket reads one unencrypted SSH binary packet and returns its payload
func readSSHPacket(r *bufio.Reader) ([]byte, error) {
	var packetLen uint32
	if err := binary.Read(r, binary.BigEndian, &packetLen); err != nil {
		return nil, fmt.Errorf("reading packet length: %w", err)
	}
	if packetLen > 35000 {
		return nil, fmt.Errorf("packet too large: %d", packetLen)
	}
	buf := make([]byte, packetLen)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("reading packet body: %w", err)
	}
	paddingLen := int(buf[0])
	end := len(buf) - paddingLen
	if end < 1 {
		return nil, fmt.Errorf("invalid padding length %d", paddingLen)
	}
	return buf[1:end], nil
}

// parseNameList parses an SSH name-list at offset in data, returns the value and new offset
func parseNameList(data []byte, offset int) (string, int, error) {
	if offset+4 > len(data) {
		return "", 0, fmt.Errorf("buffer too short at offset %d", offset)
	}
	length := int(binary.BigEndian.Uint32(data[offset:]))
	offset += 4
	if offset+length > len(data) {
		return "", 0, fmt.Errorf("name-list exceeds buffer at offset %d", offset)
	}
	return string(data[offset : offset+length]), offset + length, nil
}

// getRemoteConfig connects to a remote SSH server, reads its KEXINIT, and returns the server-side algorithm config
func getRemoteConfig(host string, port int) config {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	slog.Debug("connecting to remote host", "addr", addr)
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		slog.Error("cannot connect to remote host", "addr", addr, "err", err.Error())
		os.Exit(remoteConnError)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			slog.Debug("closing connection", "addr", addr, "err", err.Error())
		}
	}()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		slog.Error("cannot set connection deadline", "err", err.Error())
		os.Exit(remoteConnError)
	}

	r := bufio.NewReader(conn)

	banner, err := readSSHBanner(r)
	if err != nil {
		slog.Error("cannot read SSH banner", "addr", addr, "err", err.Error())
		os.Exit(remoteConnError)
	}
	slog.Debug("remote SSH banner", "banner", banner)

	if _, err := fmt.Fprintf(conn, "SSH-2.0-check-ssh\r\n"); err != nil {
		slog.Error("cannot send SSH banner", "addr", addr, "err", err.Error())
		os.Exit(remoteConnError)
	}

	payload, err := readSSHPacket(r)
	if err != nil {
		slog.Error("cannot read KEXINIT packet", "addr", addr, "err", err.Error())
		os.Exit(remoteConnError)
	}

	const sshMsgKexinit = 20
	if len(payload) < 1 || payload[0] != sshMsgKexinit {
		slog.Error("unexpected SSH message type", "expected", sshMsgKexinit, "got", payload[0])
		os.Exit(remoteConnError)
	}

	// skip message type (1 byte) + cookie (16 bytes)
	offset := 17
	fail := func(field string, err error) {
		slog.Error("cannot parse KEXINIT field", "field", field, "err", err.Error())
		os.Exit(remoteConnError)
	}

	var kexAlgos, hostKeyAlgos, encSC, macSC string
	var val string

	if val, offset, err = parseNameList(payload, offset); err != nil {
		fail("kex_algorithms", err)
	}
	kexAlgos = val

	if val, offset, err = parseNameList(payload, offset); err != nil {
		fail("server_host_key_algorithms", err)
	}
	hostKeyAlgos = val

	// skip encryption_algorithms_client_to_server
	if _, offset, err = parseNameList(payload, offset); err != nil {
		fail("encryption_algorithms_client_to_server", err)
	}

	if val, offset, err = parseNameList(payload, offset); err != nil {
		fail("encryption_algorithms_server_to_client", err)
	}
	encSC = val

	// skip mac_algorithms_client_to_server
	if _, offset, err = parseNameList(payload, offset); err != nil {
		fail("mac_algorithms_client_to_server", err)
	}

	if val, _, err = parseNameList(payload, offset); err != nil {
		fail("mac_algorithms_server_to_client", err)
	}
	macSC = val

	c := make(config)
	c["kexalgorithms"] = filterKexExtensions(kexAlgos)
	c["hostkeyalgorithms"] = hostKeyAlgos
	c["ciphers"] = encSC
	c["macs"] = macSC
	return c
}

// kexExtensions are pseudo-algorithms in KEXINIT used for capability signalling,
// not actual key exchange algorithms — ext-info-s (RFC 8308) and the Terrapin fix
// signal (OpenSSH 9.6+). Filtering them prevents false "unknown setting" warnings.
func filterKexExtensions(algos string) string {
	extensions := map[string]bool{
		"ext-info-s":                   true,
		"kex-strict-s-v00@openssh.com": true,
	}
	var result []string
	for algo := range strings.SplitSeq(algos, ",") {
		if !extensions[algo] {
			result = append(result, algo)
		}
	}
	return strings.Join(result, ",")
}

func main() {
	p := getParams()
	initLog(p.debug)

	if p.generate != "" {
		generateSnippet(p.generate, p.strict)
	}

	checked := false
	if p.host != "" {
		c := getRemoteConfig(p.host, p.port)
		KexAlgorithms(c)
		Ciphers(c)
		MACs(c)
		HostKeyAlgorithms(c)
		checked = true
	} else if p.config != "" || p.generate == "" {
		var buf []byte
		if p.config != "" {
			buf = loadSshdConfig(p.config)
		} else {
			ensureExecutedAsRoot()
			buf = getSshdConfig(p.path)
		}
		c := parseSshdConfig(buf)
		CASignatureAlgorithms(c)
		Ciphers(c)
		HostbasedAcceptedAlgorithms(c)
		HostbasedAuthentication(c)
		HostKeyAlgorithms(c)
		KexAlgorithms(c)
		MACs(c)
		PubkeyAcceptedAlgorithms(c)
		checked = true
	}

	if checked {
		slog.Info("check summary", "strict", p.strict, "warnings", cntWarn, "errors", cntErr)
		if cntErr > 0 || p.strict && cntWarn > 0 {
			slog.Error("check result: FAILED")
			os.Exit(checkFailed)
		}
		slog.Info("check result: PASSED")
	}
	os.Exit(noError)
}
