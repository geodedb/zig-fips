# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to: <security@codepros.dev>

Please include:

1. **Description** of the vulnerability
2. **Steps to reproduce** the issue
3. **Potential impact** assessment
4. **Suggested fix** (if you have one)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 1 week
- **Resolution Timeline**: Depends on severity
  - Critical: 24-72 hours
  - High: 1-2 weeks
  - Medium: 2-4 weeks
  - Low: Next release cycle

### Disclosure Policy

- We follow responsible disclosure practices
- Security advisories will be published after fixes are available
- Credit will be given to reporters (unless anonymity is requested)

## AES-GCM Nonce Handling

**Callers MUST supply a unique 12-byte nonce for every (key, message) pair.**

AES-GCM is an authenticated cipher (SP 800-38D). Its security guarantee
completely collapses if a nonce is reused under the same key: an attacker who
observes two ciphertexts encrypted with the same (key, nonce) pair can recover
the XOR of the plaintexts and forge authentication tags. This is not a
theoretical concern — it is a known practical attack class.

### Rules for callers

1. **Never reuse a nonce under the same key.** Even a single repeated
   (key, nonce) pair is catastrophic.
2. **Nonce must be exactly 12 bytes.** Both backends enforce this and return
   `error.OpensslFailure` on a wrong-length nonce.
3. **Recommended nonce strategies:**
   - **Counter nonce (preferred for high-volume paths):** use a 96-bit
     monotonic counter stored alongside the key. Rekey after at most 2^32
     encryptions under a single key (NIST SP 800-38D §8.3 limit).
   - **Random 96-bit nonce:** generate 12 cryptographically random bytes via
     `Csprng.bytes` for each message. Probability of collision is negligible
     for up to ~2^32 messages under a single key (birthday bound: rekey well
     before that limit).
4. **Rotate keys** before exhausting the counter or the birthday-bound
   message limit.

### Enforcement in this seam

`Aead.open` wipes the output buffer on authentication failure — unverified
plaintext is never accessible to the caller. Always check the return value of
`open`; a decryption error means the ciphertext or tag was tampered with.

## Security Measures

This project implements:

- **Memory Safety**: Zig's compile-time memory safety checks
- **No Undefined Behavior**: Strict adherence to defined semantics
- **Dependency Scanning**: Automated security scanning in CI
- **Secret Detection**: Gitleaks scanning for leaked credentials

## Security Best Practices

When using this library:

1. Keep dependencies updated
2. Review security advisories regularly
3. Report any suspicious behavior
4. Follow secure coding guidelines

## Contact

For non-security issues, see [SUPPORT.md](SUPPORT.md).
