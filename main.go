package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
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
	cntWarn    = 0 // total number of warnings
	cntErr     = 0 // total number of errors
	cntMissing = 0 // total number of missing required settings
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
	pathSet  bool
	portSet  bool
}

type config map[string]string

const (
	maxSSHBannerLineLen = 255
	maxSSHBannerLines   = 50
	maxSSHPacketLen     = 35000
)

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
	noError               = iota // 0
	checkUserError               // 1
	isRootError                  // 2
	sshdWrongPath                // 3
	sshdExecError                // 4
	fileReadError                // 5
	remoteConnError              // 6
	generateError                // 7
	paramError                   // 8
	incompleteConfigError        // 9
	checkFailed           = 99   // 99
)

// exitError carries an exit code alongside an error so helpers can signal
// failure without calling os.Exit themselves (which would break in-process tests).
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

func newExitError(code int, format string, args ...any) *exitError {
	return &exitError{code: code, err: fmt.Errorf(format, args...)}
}

// exitOnError exits the process with the code embedded in err, or 1 if err is
// not an *exitError. Returns immediately if err is nil.
func exitOnError(err error) {
	if err == nil {
		return
	}
	if ee, ok := errors.AsType[*exitError](err); ok {
		os.Exit(ee.code)
	}
	os.Exit(1)
}

// rule holds the security best practices classification for a single sshd_config option.
// The recList/nrList/prList fields are derived from the recommended/notRecommended/prohibited
// strings by build() and used at check time to avoid re-splitting on every call.
type rule struct {
	option         string
	recommended    string
	notRecommended string
	prohibited     string
	boolean        bool // if true, configLine emits a positive directive (not a denylist)
	recList        []string
	nrList         []string
	prList         []string
}

// build pre-splits the recommended/notRecommended/prohibited strings into slices
// so checks don't repeat the work. Intended to be chained on rule literals at package init.
func (r rule) build() rule {
	r.recList = splitAlgos(r.recommended)
	r.nrList = splitAlgos(r.notRecommended)
	r.prList = splitAlgos(r.prohibited)
	return r
}

// splitAlgos strips spaces, splits on commas, and drops empty entries.
func splitAlgos(s string) []string {
	var result []string
	for algo := range strings.SplitSeq(strings.ReplaceAll(s, " ", ""), ",") {
		if algo != "" {
			result = append(result, algo)
		}
	}
	return result
}

func (r rule) check(c config) {
	enabled, ok := c[strings.ToLower(r.option)]
	if !ok || strings.TrimSpace(enabled) == "" {
		slog.Error("missing required setting", "option", r.option)
		cntMissing++
		return
	}
	verify(r, enabled)
}

// configLine returns the sshd_config directive that removes disallowed values from the default set.
// Boolean options emit a positive directive. For algorithm lists, prohibited values are always removed;
// in strict mode not-recommended values are removed too. Returns "" if there is nothing to remove.
func (r rule) configLine(strict bool) string {
	if r.boolean {
		return r.option + " " + r.recommended
	}
	remove := slices.Clone(r.prList)
	if strict {
		remove = append(remove, r.nrList...)
	}
	if len(remove) == 0 {
		return ""
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
	}.build()
	ruleCiphers = rule{
		option:         "Ciphers",
		recommended:    "aes256-gcm@openssh.com,chacha20-poly1305@openssh.com",
		notRecommended: "aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr",
		prohibited:     "aes256-cbc,aes192-cbc,aes128-cbc,3des-cbc,arcfour,arcfour128,arcfour256,blowfish-cbc,cast128-cbc",
	}.build()
	ruleHostbasedAcceptedAlgorithms = rule{
		option: "HostbasedAcceptedAlgorithms",
		recommended: "ecdsa-sha2-nistp384,ecdsa-sha2-nistp384-cert-v01@openssh.com,rsa-sha2-512," +
			"rsa-sha2-512-cert-v01@openssh.com,ecdsa-sha2-nistp521,ecdsa-sha2-nistp521-cert-v01@openssh.com," +
			"ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com," +
			"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com",
		notRecommended: "rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com,ecdsa-sha2-nistp256," +
			"ecdsa-sha2-nistp256-cert-v01@openssh.com",
		prohibited: "ssh-rsa,ssh-rsa-cert-v01@openssh.com,ssh-dss,ssh-dss-cert-v01@openssh.com",
	}.build()
	ruleHostbasedAuthentication = rule{
		option:         "HostbasedAuthentication",
		recommended:    "no",
		notRecommended: "",
		prohibited:     "yes",
		boolean:        true,
	}.build()
	ruleHostKeyAlgorithms = rule{
		option: "HostKeyAlgorithms",
		recommended: "ecdsa-sha2-nistp384,ecdsa-sha2-nistp384-cert-v01@openssh.com,rsa-sha2-512," +
			"rsa-sha2-512-cert-v01@openssh.com,ecdsa-sha2-nistp521,ecdsa-sha2-nistp521-cert-v01@openssh.com," +
			"ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com," +
			"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com",
		notRecommended: "rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com,ecdsa-sha2-nistp256," +
			"ecdsa-sha2-nistp256-cert-v01@openssh.com",
		prohibited: "ssh-rsa,ssh-rsa-cert-v01@openssh.com,ssh-dss,ssh-dss-cert-v01@openssh.com",
	}.build()
	ruleKexAlgorithms = rule{
		option: "KexAlgorithms",
		recommended: "ecdh-sha2-nistp384,ecdh-sha2-nistp521,curve25519-sha256,curve25519-sha256@libssh.org," +
			"sntrup761x25519-sha512@openssh.com,sntrup761x25519-sha512,mlkem768x25519-sha256",
		notRecommended: "ecdh-sha2-nistp256,sntrup4591761x25519-sha512@tinyssh.org," +
			"diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256",
		prohibited: "diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group14-sha256," +
			"diffie-hellman-group-exchange-sha1",
	}.build()
	ruleMACs = rule{
		option:         "MACs",
		recommended:    "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com",
		notRecommended: "hmac-sha2-256,hmac-sha2-512,umac-128@openssh.com,umac-128-etm@openssh.com",
		prohibited: "hmac-md5,hmac-md5-96,hmac-md5-etm@openssh.com,hmac-md5-96-etm@openssh.com,hmac-sha1," +
			"hmac-sha1-96,hmac-sha1-etm@openssh.com,hmac-sha1-96-etm@openssh.com,umac-64@openssh.com," +
			"umac-64-etm@openssh.com",
	}.build()
	rulePubkeyAcceptedAlgorithms = rule{
		option: "PubkeyAcceptedAlgorithms",
		recommended: "ecdsa-sha2-nistp384,ecdsa-sha2-nistp384-cert-v01@openssh.com,rsa-sha2-512," +
			"rsa-sha2-512-cert-v01@openssh.com,ecdsa-sha2-nistp521,ecdsa-sha2-nistp521-cert-v01@openssh.com," +
			"ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com," +
			"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com",
		notRecommended: "rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com,ecdsa-sha2-nistp256," +
			"ecdsa-sha2-nistp256-cert-v01@openssh.com",
		prohibited: "ssh-rsa,ssh-rsa-cert-v01@openssh.com,ssh-dss,ssh-dss-cert-v01@openssh.com",
	}.build()

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
	flag.StringVar(&c.generate, "generate", "", `generate sshd_config.d snippet to filename (when used without value: "99-ssh-hardened.conf")`)
	flag.BoolVar(&c.strict, "strict", false, "strict check: fail on warnings")
	flag.BoolVar(&c.version, "version", false, "print program version and quit")
	flag.BoolVar(&c.debug, "debug", false, "increase logging level")
	flag.BoolVar(&c.help, "help", false, "print help and exit")
	flag.Parse()
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "path":
			c.pathSet = true
		case "port":
			c.portSet = true
		}
	})

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

func validateParams(c params) error {
	if c.generate != "" {
		if c.host != "" {
			return fmt.Errorf("-generate cannot be combined with -host")
		}
		if c.config != "" {
			return fmt.Errorf("-generate cannot be combined with -config")
		}
		if c.pathSet {
			return fmt.Errorf("-generate cannot be combined with -path")
		}
		if c.portSet {
			return fmt.Errorf("-generate cannot be combined with -port")
		}
	}
	if c.host != "" && c.config != "" {
		return fmt.Errorf("-host cannot be combined with -config")
	}
	if c.port < 1 || c.port > 65535 {
		return fmt.Errorf("-port must be between 1 and 65535, got %d", c.port)
	}
	return nil
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

func ensureExecutedAsRoot() error {
	slog.Debug("ensuring program is running as root user")
	u, err := user.Current()
	if err != nil {
		slog.Error("unable to get current user", "err", err.Error())
		return newExitError(checkUserError, "unable to get current user: %w", err)
	}
	if u.Username != "root" {
		slog.Error("program must be executed by root", "current_user", u.Username)
		return newExitError(isRootError, "program must be executed by root (current user: %s)", u.Username)
	}
	return nil
}

// return parsed sshd config as a map
func parseSshdConfig(buf []byte) config {
	slog.Debug("parsing sshd config")
	c := make(config)
	for line := range strings.SplitSeq(string(buf), "\n") {
		line = strings.TrimRight(line, "\r")
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, _ := strings.Cut(line, " ")
		c[strings.ToLower(key)] = value
	}
	return c
}

// execute sshd -T, grab output and return parsed config as a map
func getSshdConfig(path string) ([]byte, error) {
	slog.Debug("getting config from 'sshd -T' command", "path", path)
	p, err := exec.LookPath(path)
	if err != nil {
		slog.Error("cannot locate sshd binary", "err", err.Error())
		return nil, newExitError(sshdWrongPath, "cannot locate sshd binary: %w", err)
	}
	slog.Debug("sshd binary", "path", p)
	buf, err := exec.CommandContext(context.Background(), p, "-T").Output() // #nosec G204 -- sshd path is an explicit CLI input for this admin tool.
	if err != nil {
		slog.Error("error executing sshd -T", "path", p, "err", err.Error())
		return nil, newExitError(sshdExecError, "error executing sshd -T at %s: %w", p, err)
	}
	return buf, nil
}

// load sshd config from file, parse it and return as a map
// the file must contain an output from 'sshd -T' command
func loadSshdConfig(file string) ([]byte, error) {
	slog.Debug("getting sshd config from specified file", "file", file)
	buf, err := os.ReadFile(file) // #nosec G304 -- config file path is an explicit CLI input for offline checks.
	if err != nil {
		slog.Error("cannot load specified file", "err", err.Error())
		return nil, newExitError(fileReadError, "cannot load specified file: %w", err)
	}
	return buf, nil
}

// verify if enabled options match recommended, not recommended or prohibited lists
func verify(r rule, enabled string) {
	slog.Info("verifying", "option", r.option)
	slog.Debug("enabled values", "option", r.option, "values", enabled)
	slog.Debug("recommended values", "option", r.option, "values", r.recommended)
	slog.Debug("not recommended values", "option", r.option, "values", r.notRecommended)
	slog.Debug("prohibited values", "option", r.option, "values", r.prohibited)
	for _, v := range splitAlgos(enabled) {
		switch {
		case slices.Contains(r.recList, v):
			slog.Info("found recommended setting", "option", r.option, "value", v)
		case slices.Contains(r.nrList, v):
			slog.Warn("found not recommended setting", "option", r.option, "value", v)
			cntWarn++
		case slices.Contains(r.prList, v):
			slog.Error("found prohibited setting", "option", r.option, "value", v)
			cntErr++
		default:
			slog.Warn("found unknown setting", "option", r.option, "value", v)
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
func generateSnippet(path string, strict bool) error {
	slog.Info("generating sshd_config.d snippet", "path", path, "strict", strict)
	var sb strings.Builder
	fmt.Fprintf(&sb, "# Generated by check-ssh %s (commit: %s)\n", version, commit)
	fmt.Fprintf(&sb, "# strict: %v\n", strict)
	for _, r := range localRules {
		line := r.configLine(strict)
		if line == "" {
			continue
		}
		fmt.Fprintln(&sb, line)
	}
	if err := os.WriteFile(path, []byte(sb.String()), 0o644); err != nil { // #nosec G306 -- config snippet is not a secret
		slog.Error("cannot write snippet", "path", path, "err", err.Error())
		return newExitError(generateError, "cannot write snippet to %s: %w", path, err)
	}
	slog.Info("snippet written", "path", path)
	if strings.HasPrefix(filepath.Clean(path), "/etc/") {
		u, err := user.Current()
		if err == nil && u.Username != "root" {
			slog.Warn("snippet was written but is not owned by root; sshd will refuse to load it until you run: sudo chown root:root " + path)
		}
	}
	return nil
}

// readSSHBanner reads lines from r until it finds the server's SSH identification string
func readSSHBanner(r *bufio.Reader) (string, error) {
	for range maxSSHBannerLines {
		line, err := r.ReadSlice('\n')
		if err == bufio.ErrBufferFull {
			return "", fmt.Errorf("SSH banner line too long")
		}
		if err != nil {
			return "", fmt.Errorf("reading SSH banner: %w", err)
		}
		if len(line) > maxSSHBannerLineLen {
			return "", fmt.Errorf("SSH banner line too long")
		}
		text := strings.TrimRight(string(line), "\r\n")
		if strings.HasPrefix(text, "SSH-") {
			return text, nil
		}
	}
	return "", fmt.Errorf("too many lines before SSH banner")
}

// readSSHPacket reads one unencrypted SSH binary packet and returns its payload
func readSSHPacket(r *bufio.Reader) ([]byte, error) {
	var packetLen uint32
	if err := binary.Read(r, binary.BigEndian, &packetLen); err != nil {
		return nil, fmt.Errorf("reading packet length: %w", err)
	}
	if packetLen < 5 {
		return nil, fmt.Errorf("invalid packet length: %d", packetLen)
	}
	if packetLen > maxSSHPacketLen {
		return nil, fmt.Errorf("packet too large: %d", packetLen)
	}
	buf := make([]byte, packetLen)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("reading packet body: %w", err)
	}
	paddingLen := int(buf[0])
	if paddingLen < 4 {
		return nil, fmt.Errorf("invalid padding length %d", paddingLen)
	}
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
func getRemoteConfig(host string, port int) (config, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	slog.Debug("connecting to remote host", "addr", addr)
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		slog.Error("cannot connect to remote host", "addr", addr, "err", err.Error())
		return nil, newExitError(remoteConnError, "cannot connect to remote host %s: %w", addr, err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			slog.Debug("closing connection", "addr", addr, "err", err.Error())
		}
	}()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		slog.Error("cannot set connection deadline", "err", err.Error())
		return nil, newExitError(remoteConnError, "cannot set connection deadline: %w", err)
	}

	r := bufio.NewReader(conn)

	banner, err := readSSHBanner(r)
	if err != nil {
		slog.Error("cannot read SSH banner", "addr", addr, "err", err.Error())
		return nil, newExitError(remoteConnError, "cannot read SSH banner from %s: %w", addr, err)
	}
	slog.Debug("remote SSH banner", "banner", banner)

	if _, err := fmt.Fprintf(conn, "SSH-2.0-check-ssh\r\n"); err != nil {
		slog.Error("cannot send SSH banner", "addr", addr, "err", err.Error())
		return nil, newExitError(remoteConnError, "cannot send SSH banner to %s: %w", addr, err)
	}

	payload, err := readSSHPacket(r)
	if err != nil {
		slog.Error("cannot read KEXINIT packet", "addr", addr, "err", err.Error())
		return nil, newExitError(remoteConnError, "cannot read KEXINIT packet from %s: %w", addr, err)
	}

	if err := validateKEXINITPayload(payload); err != nil {
		slog.Error("unexpected SSH packet payload", "err", err.Error())
		return nil, newExitError(remoteConnError, "unexpected SSH packet payload: %w", err)
	}

	// skip message type (1 byte) + cookie (16 bytes)
	offset := 17
	parseField := func(field string) (string, error) {
		v, off, err := parseNameList(payload, offset)
		if err != nil {
			slog.Error("cannot parse KEXINIT field", "field", field, "err", err.Error())
			return "", newExitError(remoteConnError, "cannot parse KEXINIT field %s: %w", field, err)
		}
		offset = off
		return v, nil
	}

	kexAlgos, err := parseField("kex_algorithms")
	if err != nil {
		return nil, err
	}
	hostKeyAlgos, err := parseField("server_host_key_algorithms")
	if err != nil {
		return nil, err
	}
	encCS, err := parseField("encryption_algorithms_client_to_server")
	if err != nil {
		return nil, err
	}
	encSC, err := parseField("encryption_algorithms_server_to_client")
	if err != nil {
		return nil, err
	}
	macCS, err := parseField("mac_algorithms_client_to_server")
	if err != nil {
		return nil, err
	}
	macSC, err := parseField("mac_algorithms_server_to_client")
	if err != nil {
		return nil, err
	}

	c := make(config)
	c["kexalgorithms"] = filterKexExtensions(kexAlgos)
	c["hostkeyalgorithms"] = hostKeyAlgos
	c["ciphers"] = mergeAlgos(encCS, encSC)
	c["macs"] = mergeAlgos(macCS, macSC)
	return c, nil
}

// mergeAlgos returns the union of two comma-separated algorithm lists, preserving
// the order of first appearance. Used to surface weak algorithms advertised in
// either direction when the server's client-to-server and server-to-client lists differ.
func mergeAlgos(a, b string) string {
	seen := make(map[string]bool)
	var result []string
	for _, list := range []string{a, b} {
		for algo := range strings.SplitSeq(list, ",") {
			if algo == "" || seen[algo] {
				continue
			}
			seen[algo] = true
			result = append(result, algo)
		}
	}
	return strings.Join(result, ",")
}

func validateKEXINITPayload(payload []byte) error {
	const sshMsgKexinit = 20
	if len(payload) < 1 {
		return fmt.Errorf("empty payload, expected message type %d", sshMsgKexinit)
	}
	if payload[0] != sshMsgKexinit {
		return fmt.Errorf("expected message type %d, got %d", sshMsgKexinit, payload[0])
	}
	return nil
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
	if err := validateParams(p); err != nil {
		slog.Error("invalid arguments", "err", err.Error())
		os.Exit(paramError)
	}

	if p.generate != "" {
		exitOnError(generateSnippet(p.generate, p.strict))
		os.Exit(noError)
	}

	if p.host != "" {
		c, err := getRemoteConfig(p.host, p.port)
		exitOnError(err)
		KexAlgorithms(c)
		Ciphers(c)
		MACs(c)
		HostKeyAlgorithms(c)
	} else {
		var buf []byte
		var err error
		if p.config != "" {
			buf, err = loadSshdConfig(p.config)
		} else {
			exitOnError(ensureExecutedAsRoot())
			buf, err = getSshdConfig(p.path)
		}
		exitOnError(err)
		c := parseSshdConfig(buf)
		CASignatureAlgorithms(c)
		Ciphers(c)
		HostbasedAcceptedAlgorithms(c)
		HostbasedAuthentication(c)
		HostKeyAlgorithms(c)
		KexAlgorithms(c)
		MACs(c)
		PubkeyAcceptedAlgorithms(c)
	}

	slog.Info("check summary", "strict", p.strict, "warnings", cntWarn, "errors", cntErr, "missing", cntMissing)
	if cntMissing > 0 {
		slog.Error("check result: INCOMPLETE CONFIG")
		os.Exit(incompleteConfigError)
	}
	if cntErr > 0 || (p.strict && cntWarn > 0) {
		slog.Error("check result: FAILED")
		os.Exit(checkFailed)
	}
	slog.Info("check result: PASSED")
	os.Exit(noError)
}
