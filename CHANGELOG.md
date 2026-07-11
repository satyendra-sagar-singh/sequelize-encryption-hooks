# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-11

### Added

- Transparent field-level encryption for Sequelize v6 models using AES-256-GCM with a random IV per value.
- Lifecycle-hook coverage for `create`, `save`, `Model.update`, `bulkCreate`, `upsert`, all find methods, `raw: true` results, and nested `include`s of registered models.
- Blind indexes (HMAC-SHA256) via `searchable` field config, with `hash()` and `whereHash()` helpers for exact-match lookups on encrypted columns.
- Key rotation via `legacyKeys`; optional pinned `hashKey` (HKDF-derived from the main key by default).
- Two configuration styles: explicit field lists in `addTo()`, or typed inline `encrypt` markers on model attributes.
- JSON serialization so numbers, booleans, and objects round-trip with their original types.
- Migration mode: pre-existing plaintext rows are returned unchanged.
- Safety guard: `upsert()` with `validate: false` throws instead of silently writing plaintext.
- `generateKey()`, `isEncrypted()`, and typed `DecryptionError` exports.
- Dual ESM/CJS build with bundled TypeScript declarations; zero runtime dependencies.

[0.1.0]: https://github.com/satyendra-sagar-singh/sequelize-encryption-hooks/releases/tag/v0.1.0
