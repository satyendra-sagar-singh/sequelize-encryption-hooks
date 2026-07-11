# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.x (latest) | ✅ |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, use one of these private channels:

- **GitHub private vulnerability reporting** (preferred): [Report a vulnerability](https://github.com/satyendra-sagar-singh/sequelize-encryption-hooks/security/advisories/new)
- **Email:** satyendra.sagar@icloud.com with subject `[SECURITY] sequelize-encryption-hooks`

You can expect an acknowledgement within 72 hours. Please include a description of the issue, steps to reproduce, and the affected version(s). Coordinated disclosure is appreciated — a fix will be prioritized and credited to you in the release notes unless you prefer otherwise.

## Scope

Reports of particular interest:

- Plaintext reaching the database through any Sequelize write path the hooks should cover
- Weaknesses in the encryption or blind-index construction (AES-256-GCM usage, IV handling, HKDF derivation, HMAC indexing)
- Key-handling flaws (key material leaking into errors, logs, or serialized output)
- Payload-parsing issues (malformed `enc:v1:` payloads causing crashes or bypasses)

Out of scope: vulnerabilities in Sequelize itself, compromised application servers (which necessarily hold the key), and equality leakage of blind indexes (a documented design property).
