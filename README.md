# check-ssh

`check-ssh` audits an SSH server's configuration against security best practices. It can inspect a local daemon, a pre-captured config file, or a remote host reached over the network.

## Installation

**Homebrew (macOS):**

```bash
brew install --cask krisiasty/tap/check-ssh
```

**Pre-built binaries** for Linux, macOS, and Windows are published on the [releases page](https://github.com/krisiasty/check-ssh/releases).

**From source** (requires Go 1.26+):

```bash
go install github.com/krisiasty/check-ssh@latest
```

## How it works

The tool operates in four modes:

**Local mode** (default) — runs `sshd -T` on the local machine to obtain the fully-resolved, active configuration, checks all supported options, and inspects each `HostKey` to verify its bit length.
It also audits the ownership and mode of the sshd configuration files and host keys against CIS recommendations, and can remediate them in place with `-fix-perms`. Requires root because `sshd -T`
needs access to host key files.

**Config-file mode** (`-config`) — reads a file containing the output of a previously captured `sshd -T` command and checks all supported options. Useful for offline/CI auditing or auditing a remote
host when you can copy the file.

**Remote mode** (`-host`) — connects to a remote SSH server, reads the unencrypted SSH handshake (`KEXINIT` message), and checks the subset of options advertised there. No credentials or
authentication are required. See [Limitations of remote mode](#limitations-of-remote-mode) below.

**Generation mode** (`-generate`) — writes an `sshd_config.d` drop-in snippet that removes disallowed algorithms from sshd's defaults. This is a standalone mode and cannot be combined with local,
config-file, or remote scanning.

In scan modes, every enabled value is classified as **recommended**, **not recommended**, **prohibited**, or **unknown** (treated as a warning). Exit codes are listed below.

## Usage

```text
check-ssh [-path <sshd>] [-strict] [-fix-perms] [-debug]
check-ssh -config <file> [-strict] [-debug]
check-ssh -host <host> [-port <port>] [-strict] [-debug]
check-ssh -generate [<file>] [-strict] [-debug]
check-ssh -version
check-ssh -help
```

### Arguments

| Flag                 | Default                | Description                                                                                                                 |
| -------------------- | ---------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `-path <path>`       | `/usr/sbin/sshd`       | Path to the `sshd` binary (local mode only).                                                                                |
| `-config <file>`     | —                      | Path to a saved `sshd -T` output; skips running sshd locally.                                                               |
| `-host <host>`       | —                      | Hostname or IP of a remote SSH server to scan.                                                                              |
| `-port <port>`       | `22`                   | TCP port for remote scanning.                                                                                               |
| `-generate [<file>]` | `00-ssh-hardened.conf` | Write an `sshd_config.d` drop-in snippet that removes disallowed algorithms. Must be used standalone.                       |
| `-strict`            | false                  | Treat _not-recommended_ findings as failures (exit 99). Also removes not-recommended algorithms from the generated snippet. |
| `-fix-perms`         | false                  | Remediate ownership/mode of sshd config and host key files to CIS recommendations (local mode only; cannot combine with `-config`/`-host`/`-generate`). |
| `-debug`             | false                  | Increase log verbosity.                                                                                                     |
| `-version`           | —                      | Print version, commit, and build date, then exit.                                                                           |
| `-help`              | —                      | Print usage and exit.                                                                                                       |

### Exit codes

| Code | Meaning                                        |
| ---- | ---------------------------------------------- |
| `0`  | No issues found (or generate-only run).        |
| `1`  | Could not determine current user.              |
| `2`  | Must be run as root (local mode).              |
| `3`  | `sshd` binary not found at the specified path. |
| `4`  | `sshd -T` execution failed.                    |
| `5`  | Could not read the specified config file.      |
| `6`  | Remote connection or handshake failed.         |
| `7`  | Could not write the generated snippet.         |
| `8`  | Invalid argument combination.                  |
| `9`  | Config is incomplete or missing required keys. |
| `99` | One or more checks failed.                     |

---

## Checked settings and algorithm classifications

### Access control (AllowUsers / AllowGroups / DenyUsers / DenyGroups)

Restricts which users or groups may authenticate. Checked in **local and config-file modes only**.

By default sshd permits any account to authenticate, so CIS recommends configuring **at least one** of these allow/deny lists. This check is **recommended but not required**: if none of the four is
configured it reports a warning (the run still passes), while in strict mode that warning fails the run (exit 99). Configuring any one of them satisfies the check. The generated snippet emits
`AllowGroups sudo` to satisfy it — **tailor this to your environment** (replace `sudo` with the group that should have SSH access).

| Status          | Value                                                        | Reason                                                                          |
| --------------- | ------------------------------------------------------------ | ------------------------------------------------------------------------------- |
| Recommended     | at least one of `AllowUsers`/`AllowGroups`/`DenyUsers`/`DenyGroups` | Explicitly bounds who may log in, rather than permitting every account. |
| Not recommended | none configured                                              | sshd allows any account to authenticate; access is not restricted by policy.    |

---

### CASignatureAlgorithms

Algorithms accepted for CA signatures on certificates. Checked in **local and config-file modes only**.

| Status          | Algorithm                            | Reason                                                                            |
| --------------- | ------------------------------------ | --------------------------------------------------------------------------------- |
| Recommended     | `ecdsa-sha2-nistp384`                | ECDSA on P-384 provides strong 192-bit security for CA signing.                   |
| Recommended     | `ecdsa-sha2-nistp521`                | Highest-security NIST curve; appropriate for long-lived CA keys.                  |
| Recommended     | `rsa-sha2-512`                       | RSA with SHA-512; SHA-2 keeps this acceptable for RSA-based CA keys.              |
| Recommended     | `ssh-ed25519`                        | Ed25519 is fast, well-analyzed, and immune to ECDSA nonce-reuse pitfalls.         |
| Recommended     | `sk-ecdsa-sha2-nistp256@openssh.com` | Hardware-security-key backed CA; private key never leaves the device.             |
| Recommended     | `sk-ssh-ed25519@openssh.com`         | Hardware-security-key backed Ed25519 CA; hardware-protected signing.              |
| Not recommended | `rsa-sha2-256`                       | RSA with SHA-256 is technically sound but SHA-512 is preferred for CA operations. |
| Not recommended | `ecdsa-sha2-nistp256`                | P-256 offers only 128-bit security — weaker margin than P-384/521 for CA use.     |
| Prohibited      | `ssh-rsa`                            | Uses SHA-1, which is cryptographically deprecated.                                |
| Prohibited      | `ssh-dss`                            | DSA is limited to 1024-bit keys and deprecated by NIST.                           |

---

### Ciphers

Symmetric ciphers used to encrypt the session payload.

| Status          | Algorithm                       | Reason                                                                                  |
| --------------- | ------------------------------- | --------------------------------------------------------------------------------------- |
| Recommended     | `aes256-gcm@openssh.com`        | AES-256-GCM provides authenticated encryption; immune to CBC padding attacks.           |
| Recommended     | `chacha20-poly1305@openssh.com` | ChaCha20-Poly1305 is timing-attack resistant and excels in software implementations.    |
| Not recommended | `aes128-gcm@openssh.com`        | Authenticated GCM mode but 128-bit key offers less security margin than 256-bit.        |
| Not recommended | `aes256-ctr`                    | CTR mode lacks built-in authentication; relies entirely on a separate MAC.              |
| Not recommended | `aes192-ctr`                    | As above; additionally 192-bit key size has no meaningful advantage in practice.        |
| Not recommended | `aes128-ctr`                    | CTR mode without authentication; weakest CTR variant still in use.                      |
| Prohibited      | `aes256-cbc`                    | CBC mode is vulnerable to padding oracle attacks (BEAST, Lucky13).                      |
| Prohibited      | `aes192-cbc`                    | Same CBC weakness as AES-256-CBC.                                                       |
| Prohibited      | `aes128-cbc`                    | Same CBC weakness with a shorter key, doubling the exposure.                            |
| Prohibited      | `3des-cbc`                      | Obsolete cipher with 112-bit effective strength and a 64-bit block prone to Sweet32.    |
| Prohibited      | `arcfour`                       | RC4 has multiple known biases and is considered broken.                                 |
| Prohibited      | `arcfour128`                    | RC4 variant — inherits the same fundamental weaknesses.                                 |
| Prohibited      | `arcfour256`                    | RC4 variant — key length does not fix the stream-cipher biases.                         |
| Prohibited      | `blowfish-cbc`                  | 64-bit block size is vulnerable to Sweet32 birthday attacks.                            |
| Prohibited      | `cast128-cbc`                   | 64-bit block cipher in CBC mode; vulnerable to both padding oracle and Sweet32 attacks. |

---

### ClientAliveInterval

Idle timeout: seconds between keepalive probes the server sends to an inactive client. Checked in **local and config-file modes only**.

Recommended for CIS compliance to bound idle sessions. This setting is **recommended but not required**: in normal mode an absent or non-compliant value is reported as a warning (the run still
passes), while in strict mode that warning fails the run (exit 99). Any non-zero interval of at most 300 seconds is accepted — a **stricter (smaller) timeout passes**; only `0` (timeouts disabled)
or a value above 300 warns. Works together with [ClientAliveCountMax](#clientalivecountmax) — `ClientAliveInterval 300` with `ClientAliveCountMax 0` disconnects an idle client after 300 seconds.
The generated snippet always emits `ClientAliveInterval 300`.

| Status          | Value            | Reason                                                                            |
| --------------- | ---------------- | --------------------------------------------------------------------------------- |
| Recommended     | `1`–`300`        | Non-zero idle timeout of at most 300 seconds; a stricter (smaller) value is fine. |
| Not recommended | `0` or `> 300`   | `0` disables idle timeouts entirely; larger values exceed the CIS recommendation. |

---

### ClientAliveCountMax

Number of missed keepalive probes tolerated before the server disconnects an unresponsive client. Checked in **local and config-file modes only**.

Recommended for CIS compliance. This setting is **recommended but not required**: in normal mode an absent or differing value is reported as a warning (the run still passes), while in strict mode
that warning fails the run (exit 99). With `ClientAliveCountMax 0` and [ClientAliveInterval](#clientaliveinterval) `300`, the server disconnects an idle client after the first missed probe (300
seconds). The generated snippet always emits `ClientAliveCountMax 0`.

| Status          | Value   | Reason                                                                                      |
| --------------- | ------- | ------------------------------------------------------------------------------------------- |
| Recommended     | `0`     | Disconnects an idle client on the first missed probe; the tightest CIS-recommended timeout. |
| Not recommended | other   | Larger values extend how long an idle or dropped session lingers before disconnect.         |

---

### HostbasedAcceptedAlgorithms

Algorithms accepted for host-based client authentication. Checked in **local and config-file modes only**.

| Status          | Algorithm                                     | Reason                                                                 |
| --------------- | --------------------------------------------- | ---------------------------------------------------------------------- |
| Recommended     | `ecdsa-sha2-nistp384`                         | Strong 192-bit ECDSA; good baseline for host authentication.           |
| Recommended     | `ecdsa-sha2-nistp384-cert-v01@openssh.com`    | Certificate variant adds revocation support to the P-384 algorithm.    |
| Recommended     | `rsa-sha2-512`                                | RSA with SHA-512; only RSA variant acceptable for host authentication. |
| Recommended     | `rsa-sha2-512-cert-v01@openssh.com`           | Certificate variant of RSA-SHA-512 with revocation support.            |
| Recommended     | `ecdsa-sha2-nistp521`                         | Highest-security NIST curve for host keys.                             |
| Recommended     | `ecdsa-sha2-nistp521-cert-v01@openssh.com`    | Certificate variant of P-521.                                          |
| Recommended     | `ssh-ed25519`                                 | Fast, widely supported, and immune to ECDSA implementation pitfalls.   |
| Recommended     | `ssh-ed25519-cert-v01@openssh.com`            | Certificate variant of Ed25519.                                        |
| Recommended     | `sk-ecdsa-sha2-nistp256@openssh.com`          | Security-key backed ECDSA; private key protected by hardware.          |
| Recommended     | `sk-ecdsa-sha2-nistp256-cert-v01@openssh.com` | Certificate variant of hardware-backed ECDSA.                          |
| Recommended     | `sk-ssh-ed25519@openssh.com`                  | Security-key backed Ed25519; hardware-protected signing.               |
| Recommended     | `sk-ssh-ed25519-cert-v01@openssh.com`         | Certificate variant of hardware-backed Ed25519.                        |
| Not recommended | `rsa-sha2-256`                                | RSA with SHA-256 is weaker than SHA-512 for host key signing.          |
| Not recommended | `rsa-sha2-256-cert-v01@openssh.com`           | Certificate variant inherits the same SHA-256 weakness.                |
| Not recommended | `ecdsa-sha2-nistp256`                         | P-256 offers only 128-bit security — prefer P-384 or P-521.            |
| Not recommended | `ecdsa-sha2-nistp256-cert-v01@openssh.com`    | Certificate variant of P-256 — same weaker security margin.            |
| Prohibited      | `ssh-rsa`                                     | Uses SHA-1; deprecated and unsafe.                                     |
| Prohibited      | `ssh-rsa-cert-v01@openssh.com`                | Certificate variant of the deprecated SSH-RSA.                         |
| Prohibited      | `ssh-dss`                                     | DSA is limited to 1024 bits and deprecated.                            |
| Prohibited      | `ssh-dss-cert-v01@openssh.com`                | Certificate variant of the deprecated DSA.                             |

---

### HostbasedAuthentication

Controls whether host-based client authentication is enabled at all. Checked in **local and config-file modes only**.

| Status      | Value | Reason                                                                                             |
| ----------- | ----- | -------------------------------------------------------------------------------------------------- |
| Recommended | `no`  | Host-based authentication relies on client hostnames which can be spoofed.                         |
| Prohibited  | `yes` | Enabling it allows any trusted-but-compromised client host to authenticate on behalf of its users. |

---

### HostKeyAlgorithms

Algorithms the server uses to authenticate itself to clients.

| Status          | Algorithm                                     | Reason                                                                          |
| --------------- | --------------------------------------------- | ------------------------------------------------------------------------------- |
| Recommended     | `ecdsa-sha2-nistp384`                         | Strong 192-bit ECDSA server host key.                                           |
| Recommended     | `ecdsa-sha2-nistp384-cert-v01@openssh.com`    | Certificate variant enables centralized host key management.                    |
| Recommended     | `rsa-sha2-512`                                | RSA host key with SHA-512; only RSA variant acceptable for host authentication. |
| Recommended     | `rsa-sha2-512-cert-v01@openssh.com`           | Certificate variant of RSA-SHA-512.                                             |
| Recommended     | `ecdsa-sha2-nistp521`                         | Highest-security NIST curve for server identity.                                |
| Recommended     | `ecdsa-sha2-nistp521-cert-v01@openssh.com`    | Certificate variant of P-521.                                                   |
| Recommended     | `ssh-ed25519`                                 | Fast, compact key with strong security and wide support.                        |
| Recommended     | `ssh-ed25519-cert-v01@openssh.com`            | Certificate variant of Ed25519.                                                 |
| Recommended     | `sk-ecdsa-sha2-nistp256@openssh.com`          | Security-key backed server key; protected by hardware.                          |
| Recommended     | `sk-ecdsa-sha2-nistp256-cert-v01@openssh.com` | Certificate variant of hardware-backed ECDSA.                                   |
| Recommended     | `sk-ssh-ed25519@openssh.com`                  | Security-key backed Ed25519 host key.                                           |
| Recommended     | `sk-ssh-ed25519-cert-v01@openssh.com`         | Certificate variant of hardware-backed Ed25519.                                 |
| Not recommended | `rsa-sha2-256`                                | RSA with SHA-256 is weaker than SHA-512 for host keys.                          |
| Not recommended | `rsa-sha2-256-cert-v01@openssh.com`           | Certificate variant inherits the SHA-256 weakness.                              |
| Not recommended | `ecdsa-sha2-nistp256`                         | P-256 offers only 128-bit security — prefer P-384 or P-521.                     |
| Not recommended | `ecdsa-sha2-nistp256-cert-v01@openssh.com`    | Certificate variant of P-256.                                                   |
| Prohibited      | `ssh-rsa`                                     | SHA-1 based; deprecated.                                                        |
| Prohibited      | `ssh-rsa-cert-v01@openssh.com`                | Certificate variant of the deprecated SSH-RSA.                                  |
| Prohibited      | `ssh-dss`                                     | 1024-bit DSA; deprecated and cryptographically weak.                            |
| Prohibited      | `ssh-dss-cert-v01@openssh.com`                | Certificate variant of the deprecated DSA.                                      |

---

### IgnoreRhosts

Controls whether `.rhosts` and `.shosts` files are ignored during host-based authentication. Checked in **local and config-file modes only**.

Recommended for CIS compliance. This setting is **recommended but not required**: in normal mode an absent or differing value is reported as a warning (the run still passes), while in strict mode
that warning fails the run (exit 99). The generated snippet always emits `IgnoreRhosts yes`.

| Status          | Value        | Reason                                                                                             |
| --------------- | ------------ | -------------------------------------------------------------------------------------------------- |
| Recommended     | `yes`        | Ignores user `.rhosts`/`.shosts` files, preventing trust relationships that bypass key-based auth. |
| Not recommended | other / `no` | Honors `.rhosts`/`.shosts`, allowing users to establish spoofable host-based trust.                |

---

### KexAlgorithms

Key exchange algorithms used to establish a shared session secret.

| Status          | Algorithm                                | Reason                                                                                     |
| --------------- | ---------------------------------------- | ------------------------------------------------------------------------------------------ |
| Recommended     | `ecdh-sha2-nistp384`                     | ECDH on P-384 gives 192-bit classical security.                                            |
| Recommended     | `ecdh-sha2-nistp521`                     | Strongest classical NIST ECDH curve.                                                       |
| Recommended     | `curve25519-sha256`                      | X25519 ECDH; fast, immune to common ECDSA/ECDH implementation pitfalls.                    |
| Recommended     | `curve25519-sha256@libssh.org`           | Identical algorithm; OpenSSH-compatibility alias for `curve25519-sha256`.                  |
| Recommended     | `sntrup761x25519-sha512@openssh.com`     | Hybrid post-quantum KEX (NTRU Prime + X25519); protects against harvest-now-decrypt-later. |
| Recommended     | `sntrup761x25519-sha512`                 | Standardized name for the same NTRU Prime + X25519 hybrid.                                 |
| Recommended     | `mlkem768x25519-sha256`                  | Hybrid post-quantum KEX (ML-KEM-768/Kyber + X25519); uses NIST-standardized PQC algorithm. |
| Not recommended | `ecdh-sha2-nistp256`                     | P-256 ECDH gives only 128-bit security; adequate today but no longer the preferred choice. |
| Not recommended | `sntrup4591761x25519-sha512@tinyssh.org` | Older NTRU Prime variant; superseded by the OpenSSH `sntrup761` variants.                  |
| Not recommended | `diffie-hellman-group16-sha512`          | Classical finite-field DH (4096-bit); slow and provides no post-quantum protection.        |
| Not recommended | `diffie-hellman-group18-sha512`          | 8192-bit DH; extremely slow with no practical security advantage over group16.             |
| Not recommended | `diffie-hellman-group-exchange-sha256`   | Group quality depends on server-side parameters; better alternatives exist.                |
| Prohibited      | `diffie-hellman-group1-sha1`             | 768-bit Oakley group broken by the Logjam attack.                                          |
| Prohibited      | `diffie-hellman-group14-sha1`            | 2048-bit DH with deprecated SHA-1 hash.                                                    |
| Prohibited      | `diffie-hellman-group14-sha256`          | 2048-bit DH has insufficient security margin and no post-quantum protection.               |
| Prohibited      | `diffie-hellman-group-exchange-sha1`     | SHA-1 based group exchange; deprecated hash algorithm.                                     |

---

### LoginGraceTime

Seconds the server waits for a client to authenticate before disconnecting. Checked in **local and config-file modes only**.

Recommended for CIS compliance to limit the window for unauthenticated connections (which also mitigates resource-exhaustion from half-open sessions). This setting is **recommended but not
required**: in normal mode an absent or non-compliant value is reported as a warning (the run still passes), while in strict mode that warning fails the run (exit 99). Any non-zero grace period of at
most 60 seconds is accepted — a **stricter (smaller) value passes**; only `0` (no limit) or a value above 60 warns. The generated snippet always emits `LoginGraceTime 60`.

| Status          | Value          | Reason                                                                            |
| --------------- | -------------- | --------------------------------------------------------------------------------- |
| Recommended     | `1`–`60`       | Bounds the unauthenticated window to at most 60 seconds; a smaller value is fine. |
| Not recommended | `0` or `> 60`  | `0` removes the limit entirely; larger values exceed the CIS recommendation.      |

---

### MACs

Message authentication codes used to verify session integrity.

| Status          | Algorithm                       | Reason                                                                                       |
| --------------- | ------------------------------- | -------------------------------------------------------------------------------------------- |
| Recommended     | `hmac-sha2-256-etm@openssh.com` | Encrypt-then-MAC with SHA-256; ETM construction prevents CBC padding oracle attacks.         |
| Recommended     | `hmac-sha2-512-etm@openssh.com` | Encrypt-then-MAC with SHA-512; strongest standard HMAC variant.                              |
| Not recommended | `hmac-sha2-256`                 | MAC-then-encrypt order is less secure than ETM; vulnerable if ciphers with padding are used. |
| Not recommended | `hmac-sha2-512`                 | Same MAC-then-encrypt concern as `hmac-sha2-256`.                                            |
| Not recommended | `umac-128@openssh.com`          | UMAC is fast but uses MAC-then-encrypt; less analyzed than HMAC.                             |
| Not recommended | `umac-128-etm@openssh.com`      | ETM construction is correct, but UMAC is less scrutinized than HMAC-SHA-2.                   |
| Prohibited      | `hmac-md5`                      | MD5 is cryptographically broken.                                                             |
| Prohibited      | `hmac-md5-96`                   | Truncated MD5 MAC; broken underlying hash and short tag.                                     |
| Prohibited      | `hmac-md5-etm@openssh.com`      | ETM ordering does not rescue the broken MD5 primitive.                                       |
| Prohibited      | `hmac-md5-96-etm@openssh.com`   | Truncated MD5 with ETM; broken underlying hash.                                              |
| Prohibited      | `hmac-sha1`                     | SHA-1 is deprecated for MAC use.                                                             |
| Prohibited      | `hmac-sha1-96`                  | Truncated SHA-1 MAC; deprecated hash and short tag.                                          |
| Prohibited      | `hmac-sha1-etm@openssh.com`     | ETM ordering does not rescue the deprecated SHA-1 primitive.                                 |
| Prohibited      | `hmac-sha1-96-etm@openssh.com`  | Truncated SHA-1 with ETM; deprecated.                                                        |
| Prohibited      | `umac-64@openssh.com`           | 64-bit authentication tag is too short for modern security requirements.                     |
| Prohibited      | `umac-64-etm@openssh.com`       | ETM with a 64-bit tag; tag length is insufficient regardless of construction.                |

---

### PermitEmptyPasswords

Controls whether the server allows login to accounts with empty passwords. Checked in **local and config-file modes only**.

| Status      | Value | Reason                                                                                                 |
| ----------- | ----- | ------------------------------------------------------------------------------------------------------ |
| Recommended | `no`  | Accounts with empty passwords must never be reachable over the network.                                |
| Prohibited  | `yes` | Permits password authentication against blank-password accounts, trivially bypassing authentication.   |

---

### PermitRootLogin

Controls whether the root user may log in directly over SSH. Checked in **local and config-file modes only**.

Recommended for CIS compliance. This setting is **recommended but not required**: in normal mode an absent or differing value is reported as a warning (the run still passes), while in strict mode
that warning fails the run (exit 99). The generated snippet always emits `PermitRootLogin no`.

| Status          | Value                               | Reason                                                                                     |
| --------------- | ----------------------------------- | ------------------------------------------------------------------------------------------ |
| Recommended     | `no`                                | Disables direct root login; administrators log in as a normal user and escalate.           |
| Not recommended | other (`yes` / `prohibit-password`) | Any value other than `no` permits some form of direct root login over SSH.                 |

---

### PermitUserEnvironment

Controls whether the server processes user `~/.ssh/environment` files and `environment=` options in `authorized_keys`. Checked in **local and config-file modes only**.

Recommended for CIS compliance. This setting is **recommended but not required**: in normal mode an absent or differing value is reported as a warning (the run still passes), while in strict mode
that warning fails the run (exit 99). The generated snippet always emits `PermitUserEnvironment no`.

| Status          | Value         | Reason                                                                                              |
| --------------- | ------------- | --------------------------------------------------------------------------------------------------- |
| Recommended     | `no`          | Prevents users from setting environment variables (e.g. `LD_PRELOAD`) that can bypass restrictions. |
| Not recommended | other / `yes` | Lets users inject environment variables at login, enabling privilege-escalation vectors.            |

---

### PubkeyAcceptedAlgorithms

Algorithms accepted for public-key client authentication. Checked in **local and config-file modes only**.

| Status          | Algorithm                                     | Reason                                                                       |
| --------------- | --------------------------------------------- | ---------------------------------------------------------------------------- |
| Recommended     | `ecdsa-sha2-nistp384`                         | Strong 192-bit ECDSA for user keys.                                          |
| Recommended     | `ecdsa-sha2-nistp384-cert-v01@openssh.com`    | Certificate variant for centralized user key management.                     |
| Recommended     | `rsa-sha2-512`                                | RSA with SHA-512; only RSA variant acceptable for user authentication.       |
| Recommended     | `rsa-sha2-512-cert-v01@openssh.com`           | Certificate variant of RSA-SHA-512.                                          |
| Recommended     | `ecdsa-sha2-nistp521`                         | Highest-security NIST curve for user keys.                                   |
| Recommended     | `ecdsa-sha2-nistp521-cert-v01@openssh.com`    | Certificate variant of P-521.                                                |
| Recommended     | `ssh-ed25519`                                 | Fast, compact, widely supported, and immune to ECDSA pitfalls.               |
| Recommended     | `ssh-ed25519-cert-v01@openssh.com`            | Certificate variant of Ed25519.                                              |
| Recommended     | `sk-ecdsa-sha2-nistp256@openssh.com`          | Security-key backed ECDSA; user private key never leaves the hardware token. |
| Recommended     | `sk-ecdsa-sha2-nistp256-cert-v01@openssh.com` | Certificate variant of hardware-backed ECDSA.                                |
| Recommended     | `sk-ssh-ed25519@openssh.com`                  | Security-key backed Ed25519; hardware-protected user authentication.         |
| Recommended     | `sk-ssh-ed25519-cert-v01@openssh.com`         | Certificate variant of hardware-backed Ed25519.                              |
| Not recommended | `rsa-sha2-256`                                | RSA with SHA-256 is weaker than SHA-512 for user key signing.                |
| Not recommended | `rsa-sha2-256-cert-v01@openssh.com`           | Certificate variant inherits the SHA-256 weakness.                           |
| Not recommended | `ecdsa-sha2-nistp256`                         | P-256 provides only 128-bit security — prefer P-384 or P-521.                |
| Not recommended | `ecdsa-sha2-nistp256-cert-v01@openssh.com`    | Certificate variant of P-256.                                                |
| Prohibited      | `ssh-rsa`                                     | Uses SHA-1; deprecated.                                                      |
| Prohibited      | `ssh-rsa-cert-v01@openssh.com`                | Certificate variant of the deprecated SSH-RSA.                               |
| Prohibited      | `ssh-dss`                                     | 1024-bit DSA; deprecated and cryptographically weak.                         |
| Prohibited      | `ssh-dss-cert-v01@openssh.com`                | Certificate variant of the deprecated DSA.                                   |

---

### Subsystem (sftp)

Selects the in-process `internal-sftp` server instead of spawning an external `sftp-server` binary. Checked in **local and config-file modes only**.

`internal-sftp` removes reliance on an external binary and makes `ChrootDirectory`-based SFTP sandboxing work reliably. This setting is **recommended but not required**: in normal mode an absent or
external sftp subsystem is reported as a warning (the run still passes), while in strict mode that warning fails the run (exit 99). The generated snippet always emits `Subsystem sftp internal-sftp`.

| Status          | Value                       | Reason                                                                            |
| --------------- | --------------------------- | --------------------------------------------------------------------------------- |
| Recommended     | `internal-sftp`             | In-process SFTP server; no external dependency and reliable chroot sandboxing.    |
| Not recommended | external `sftp-server` path | Functional, but adds an external dependency and complicates chroot sandboxing.    |
| Not recommended | (absent)                    | No sftp subsystem configured; `internal-sftp` is preferred when SFTP is offered.  |

---

### UsePAM

Controls whether the server uses Pluggable Authentication Modules for account, session, and authentication management. Checked in **local and config-file modes only**.

Recommended for CIS compliance. This setting is **recommended but not required**: in normal mode an absent or differing value is reported as a warning (the run still passes), while in strict mode
that warning fails the run (exit 99). The generated snippet always emits `UsePAM yes`.

| Status          | Value        | Reason                                                                                            |
| --------------- | ------------ | ------------------------------------------------------------------------------------------------- |
| Recommended     | `yes`        | Enables PAM account/session management, including access controls, logging, and password policy.  |
| Not recommended | other / `no` | Bypasses PAM, losing centralized account restrictions, session setup, and audit hooks.            |

---

### Host key sizes

In addition to algorithm classification, **local mode** opens each `HostKey` referenced by `sshd -T` (reading the corresponding `.pub` file beside the private key) and reports the key's bit length.
Sizes that are fixed by the algorithm name (Ed25519, Ed448, ECDSA P-256/P-384/P-521) are logged but not classified — the algorithm itself is already covered by the `HostKeyAlgorithms` rule. RSA and
DSA keys, whose sizes vary, are classified against thresholds:

| Key type | Status          | Threshold      | Reason                                                                                       |
| -------- | --------------- | -------------- | -------------------------------------------------------------------------------------------- |
| RSA      | Recommended     | ≥ 3072 bits    | NIST SP 800-57 considers 3072-bit RSA equivalent to 128-bit symmetric strength.              |
| RSA      | Not recommended | 2048–3071 bits | 2048-bit RSA (~112-bit equivalent) is acceptable today but deprecated for new use post-2030. |
| RSA      | Prohibited      | < 2048 bits    | Below NIST's minimum for any new use; 1024-bit RSA is broken in practical terms.             |
| DSA      | Prohibited      | any            | DSA host keys are limited to 1024 bits and the algorithm itself is deprecated.               |

Size checks run only in **local mode**. Config-file mode (`-config`) and remote mode (`-host`) emit a log warning that key sizes cannot be verified and skip the check — the public key bytes are not
present in `sshd -T` output and are not exchanged in the unencrypted `KEXINIT` handshake.

---

### File permissions

In **local mode**, `check-ssh` audits the ownership and mode of the sshd configuration and host keys against CIS recommendations. The `Include` directive is not followed, so only the conventional
locations below are covered:

| Path                              | Recommended    | Too permissive → error                  | Not recommended → warning     |
| --------------------------------- | -------------- | --------------------------------------- | ----------------------------- |
| `/etc/ssh/sshd_config`            | `0600` root:root | group/other **write**, non-root owner | group/other **read**          |
| `/etc/ssh/sshd_config.d/`         | `0755` root:root | group/other **write**, non-root owner | —                             |
| `/etc/ssh/sshd_config.d/*.conf`   | `0600` root:root | group/other **write**, non-root owner | group/other **read**          |
| Private host keys (`HostKey`)     | `0600` root:root | any group/other access, non-root owner | —                             |
| Public host keys (`HostKey`.pub)  | `0644` root:root | group/other **write**, non-root owner | —                             |

A non-root **group** (with no group permission bits set) is reported as a warning; a non-root **owner** or any group/other permission that grants access beyond the recommendation is an error
(exit 99). A stricter-than-recommended mode (e.g. `0400` on a config file) is accepted.

**Remediation.** Running with `-fix-perms` repairs each finding in place before re-evaluating: it sets ownership to `root:root` and clears the offending permission bits with `chmod` (only ever
removing bits, so a stricter mode is preserved). `-fix-perms` requires root, works in local mode only, and cannot be combined with `-config`, `-host`, or `-generate`.

Permission checks run only in **local mode** on **unix**; config-file mode (`-config`) and remote mode (`-host`) skip them, and on non-unix platforms they are a no-op (POSIX ownership/mode are not
meaningful there).

---

## Limitations of remote mode

Remote mode (`-host`) connects to the target over TCP, reads the SSH version banner, sends a minimal SSH identification string, and parses the server's unencrypted `KEXINIT` handshake message. No
credentials are required and no authentication takes place.

Because only the `KEXINIT` packet is inspected, **remote mode can only check four of the eighteen supported settings**:

| Checked in remote mode              | Not checked in remote mode        |
| ----------------------------------- | --------------------------------- |
| `KexAlgorithms`                     | Access control (Allow/Deny lists) |
| `HostKeyAlgorithms`                 | `CASignatureAlgorithms`           |
| `Ciphers` (server→client direction) | `ClientAliveInterval`             |
| `MACs` (server→client direction)    | `ClientAliveCountMax`             |
|                                     | `HostbasedAcceptedAlgorithms`     |
|                                     | `HostbasedAuthentication`         |
|                                     | `IgnoreRhosts`                    |
|                                     | `LoginGraceTime`                  |
|                                     | `PermitEmptyPasswords`            |
|                                     | `PermitRootLogin`                 |
|                                     | `PermitUserEnvironment`           |
|                                     | `PubkeyAcceptedAlgorithms`        |
|                                     | `Subsystem` (sftp)                |
|                                     | `UsePAM`                          |

Additional caveats:

- **Only server-to-client direction is inspected** for `Ciphers` and `MACs`; client-to-server algorithms are discarded.
- **`sshd` `Match` blocks are not reflected.** The `KEXINIT` advertisement shows the global default; per-user or per-address overrides applied after authentication are invisible.
- **Algorithm advertisement ≠ configuration.** A server may advertise algorithms that are filtered by PAM, certificates, or other post-handshake policy.
- **No snippet generation in remote mode.** `-generate` is a standalone mode and cannot be combined with any scan mode.
- **No host key size verification.** Sizes are checked only in local mode (see [Host key sizes](#host-key-sizes)).
- **No file permission auditing.** Ownership and mode are checked only in local mode (see [File permissions](#file-permissions)).
- **Network access required.** The target port (default 22) must be reachable.

For a complete audit use local mode (`sudo check-ssh`) or capture `sshd -T` output on the target and transfer it for offline analysis (`check-ssh -config <file>`).

---

## Generating and installing a configuration snippet

`check-ssh -generate` produces a drop-in `sshd_config.d` file that removes all disallowed algorithms from sshd's defaults using the `-algorithm` subtraction syntax and pins the CIS-recommended
directives. It is a standalone mode and cannot be combined with local, config-file, or remote scanning. Adding `-strict` also removes not-recommended algorithms. The file is written with mode `0600`
(owner read/write only, per CIS Benchmark 5.2.1); regenerating over an existing file also tightens its mode to `0600`.

### Generate

```bash
# Default filename (00-ssh-hardened.conf), written to the current directory:
check-ssh -generate

# Custom path, written directly to the system drop-in directory:
sudo check-ssh -generate /etc/ssh/sshd_config.d/00-ssh-hardened.conf

# Strict variant (removes not-recommended algorithms too):
sudo check-ssh -generate /etc/ssh/sshd_config.d/00-ssh-hardened.conf -strict
```

### Install snippet

1. **Ensure the drop-in directory is included.** Modern OpenSSH includes this by default, but verify that `/etc/ssh/sshd_config` contains:

   ```text
   Include /etc/ssh/sshd_config.d/*.conf
   ```

2. **Place the file in the drop-in directory with correct ownership and mode:**

   ```bash
   sudo install -o root -g root -m 600 00-ssh-hardened.conf /etc/ssh/sshd_config.d/
   ```

   > sshd silently ignores drop-in files not owned by root. Mode `0600` (root-only read/write) matches CIS Benchmark 5.2.1 for sshd configuration files.

3. **Validate the resulting configuration:**

   ```bash
   sudo sshd -t
   ```

   Fix any errors before proceeding — a misconfigured sshd may lock you out.

4. **Reload sshd** (existing sessions are not interrupted):

   ```bash
   # systemd (Debian, Ubuntu, and derivatives — unit is named ssh):
   sudo systemctl reload ssh

   # systemd (RHEL, Fedora, Arch, SUSE, and most others — unit is named sshd):
   sudo systemctl reload sshd

   # macOS:
   sudo launchctl kickstart -k system/com.openssh.sshd
   ```

5. **Verify with check-ssh:**

   ```bash
   sudo check-ssh
   ```

---

## Related tools

[ssh-audit](https://github.com/jtesta/ssh-audit) is the most established tool in this space — Python-based, actively maintained, with broader remote-scan capabilities (CVE matching, banner-based
version detection, and custom policy mode). `check-ssh` is a smaller, complementary alternative emphasizing three things: a single static binary with no runtime dependencies, auditing the live local
daemon via `sshd -T`, and generation of `sshd_config.d` drop-in snippets that subtract weak algorithms from sshd's defaults.

### Classification differences

If you also run ssh-audit against the same server, you may see different verdicts. The two tools are highly opinionated and apply different philosophies; the differences worth knowing:

**NIST P-curves.** `check-ssh` classifies `ecdh-sha2-nistp384` and `ecdh-sha2-nistp521` as _recommended_, and `ecdh-sha2-nistp256` as _not recommended_ (smaller security margin). ssh-audit flags all
NIST curves as failures, citing the unexplained seed values originally raised by djb and others. That concern is well-known but speculative — the NIST P-curves remain FIPS-approved, are mandated b
NSA's CNSA suite, and have no demonstrated weakness after 25+ years of public cryptanalysis. _If you prefer the conservative position, drop them and rely on `curve25519-sha256` and
`sntrup761x25519-sha512@openssh.com` instead._

**Algorithm breadth.** ssh-audit's `(rec) +<algorithm>` recommendations suggest _adding_ some algorithms (CTR ciphers, classical DH groups, RSA-SHA-256), while `check-ssh` classifies those as _not
recommended_ on the basis that the server already offers stronger alternatives. In short: ssh-audit proposal results in broaden compatibility (read: support old ssh clients), while `check-ssh`
recommendations are purely based on security and algorithm strength. Objectively, if a client can't speak `aes256-gcm@openssh.com` or `chacha20-poly1305@openssh.com` and `curve25519-sha256` in 2026,
the right answer is "fix the client," not "weaken the server".

---

_Local and config-file modes must be run as root (or via `sudo`) because `sshd -T` requires access to host key files._
