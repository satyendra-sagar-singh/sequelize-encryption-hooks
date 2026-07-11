# sequelize-encryption-hooks

[![npm version](https://img.shields.io/npm/v/sequelize-encryption-hooks.svg)](https://www.npmjs.com/package/sequelize-encryption-hooks)
[![CI](https://github.com/satyendra-sagar-singh/sequelize-encryption-hooks/actions/workflows/ci.yml/badge.svg)](https://github.com/satyendra-sagar-singh/sequelize-encryption-hooks/actions/workflows/ci.yml)
[![license](https://img.shields.io/npm/l/sequelize-encryption-hooks.svg)](https://github.com/satyendra-sagar-singh/sequelize-encryption-hooks/blob/main/LICENSE)

Transparent field-level encryption for [Sequelize](https://sequelize.org) v6 models. Values are encrypted with **AES-256-GCM** before they hit the database and decrypted when they come back — your application code keeps working with plaintext, while the database only ever sees ciphertext.

- 🔒 AES-256-GCM (authenticated encryption, random IV per value)
- 🪝 Pure lifecycle hooks — covers `create`, `save`, `update`, `bulkCreate`, `Model.update`, `upsert`, `findAll`/`findOne`/`findByPk`, and included associations
- 🔍 Optional **blind indexes** (HMAC-SHA256) for exact-match lookups on encrypted columns
- 🔑 Key rotation via `legacyKeys`
- 🧳 Migration-friendly: pre-existing plaintext rows are returned unchanged
- 🟦 TypeScript, zero runtime dependencies, ESM + CJS

## Install

```bash
npm install sequelize-encryption-hooks
```

`sequelize@^6` is a peer dependency.

## Quickstart

Generate a key once and store it in your secret manager / environment — never in code:

```bash
node -e "console.log(require('sequelize-encryption-hooks').generateKey())"
```

```ts
import { Sequelize, DataTypes, Model } from 'sequelize'
import { SequelizeEncryption } from 'sequelize-encryption-hooks'

const encryption = new SequelizeEncryption({
  key: process.env.DB_ENCRYPTION_KEY!, // 64-char hex, base64, or 32-byte Buffer
})

class User extends Model {}
User.init(
  {
    name: DataTypes.STRING,
    email: DataTypes.TEXT,        // encrypted
    emailHash: DataTypes.STRING,  // blind index for email lookups
    ssn: DataTypes.TEXT,          // encrypted
  },
  { sequelize, modelName: 'user' },
)

encryption.addTo(User, {
  email: { searchable: true }, // writes HMAC to emailHash on every write
  ssn: {},
})
```

That's it. From here on:

```ts
const user = await User.create({ name: 'Ada', email: 'ada@example.com', ssn: '123-45-6789' })
user.ssn // '123-45-6789' — plaintext in memory

// In the database:
// ssn = 'enc:v1:<iv>:<authTag>:<ciphertext>'

const found = await User.findOne({
  where: encryption.whereHash(User, 'email', 'ada@example.com'),
})
found.email // 'ada@example.com'
```

## Choosing which fields to encrypt

Encryption is strictly **opt-in per field** — attributes you don't configure are stored and queried as plain columns, with zero overhead. Two equivalent styles:

**1. Explicit list** — keep encryption config in one place:

```ts
encryption.addTo(User, ['ssn'])                          // simple list
encryption.addTo(User, { email: { searchable: true } })  // with per-field options
```

**2. Inline markers** — declare it on the attribute itself, then call `addTo` with no field list:

```ts
User.init(
  {
    name: DataTypes.STRING,                                    // plain
    bio: DataTypes.TEXT,                                       // plain
    ssn: { type: DataTypes.TEXT, encrypt: true },              // encrypted
    email: { type: DataTypes.TEXT, encrypt: { searchable: true } }, // encrypted + blind index
    emailHash: DataTypes.STRING,
  },
  { sequelize, modelName: 'user' },
)

encryption.addTo(User) // picks up every attribute marked with `encrypt`
```

The `encrypt` attribute option is fully typed (the package augments Sequelize's `ModelAttributeColumnOptions`), and accepts `true` or the same `{ searchable, hashField }` config as the explicit form. When a field list is passed to `addTo`, it is used as-is and markers are ignored.

## How it works

| Hook | What the plugin does |
|---|---|
| `beforeValidate` | Encrypts object/array values (Sequelize's built-in validation rejects them on string columns) |
| `afterValidate` | Encrypts all fields on the `upsert` path — upsert builds its SQL values right after validation, before `beforeUpsert` fires |
| `beforeCreate` / `beforeUpdate` / `beforeBulkCreate` | Encrypts configured fields on the instance, writes blind indexes |
| `beforeBulkUpdate` | Encrypts values passed to `Model.update()` |
| `beforeUpsert` | Safety check: throws instead of silently writing plaintext when `validate: false` is passed to `upsert` |
| `afterCreate` / `afterUpdate` / `afterBulkCreate` / `afterUpsert` | Restores plaintext on the returned instance |
| `afterFind` | Decrypts results — single instances, arrays, `raw: true` rows, and nested `include`s of registered models |

String values are encrypted **after** validation, so attribute validators (`isEmail`, `len`, …) still run against plaintext on `create`/`save`.

Values are JSON-serialized before encryption, so numbers, booleans, and objects round-trip with their original types. Encrypted payloads are self-describing (`enc:v1:` prefix), which makes the hooks idempotent — a value is never double-encrypted, and rows written before you adopted the plugin are passed through as-is.

Use `TEXT` columns for encrypted fields: ciphertext is base64 plus ~55 bytes of overhead, which can overflow `STRING(255)` for longer values.

## Searchable fields (blind index)

Encrypted columns can't be used in `WHERE` clauses — every write produces different ciphertext. For exact-match lookups, mark a field `searchable`. The plugin then writes a deterministic HMAC-SHA256 of the plaintext to a sibling column (`<field>Hash` by default, or set `hashField`):

```ts
encryption.addTo(User, { email: { searchable: true, hashField: 'emailIndex' } })

await User.findOne({ where: encryption.whereHash(User, 'email', 'ada@example.com') })
// or manually:
await User.findOne({ where: { emailIndex: encryption.hash('ada@example.com') } })
```

Add a database index on the hash column for fast lookups. Notes:

- Lookups are **exact-match and case-sensitive** — normalize (e.g. lowercase emails) before storing and querying.
- `LIKE` / range / partial matches are fundamentally not possible on encrypted data.
- The HMAC key is derived from your main key via HKDF; pass an explicit `hashKey` if you want blind indexes to survive main-key rotation without recomputing.

## Key rotation

```ts
const encryption = new SequelizeEncryption({
  key: process.env.DB_ENCRYPTION_KEY_V2!,      // new writes use this
  legacyKeys: [process.env.DB_ENCRYPTION_KEY_V1!], // old rows still decrypt
  hashKey: process.env.DB_HASH_KEY!,            // keeps blind indexes stable
})
```

Reads try the primary key first, then each legacy key. To fully re-encrypt, load and re-save rows in batches:

```ts
let rows
do {
  rows = await User.findAll({ where: { ssn: { [Op.startsWith]: 'enc:v1:' } }, limit: 500, offset })
  for (const row of rows) {
    row.changed('ssn', true) // force re-encryption with the current key
    await row.save()
  }
} while (rows.length)
```

## Migrating existing plaintext data

Register the plugin first — plaintext rows keep working (they're returned unchanged). Then encrypt in place:

```ts
const users = await User.findAll()
for (const user of users) {
  user.changed('ssn', true)
  await user.save()
}
```

## API

### `new SequelizeEncryption(options)`

| Option | Type | Description |
|---|---|---|
| `key` | `string \| Buffer` | Required. 32-byte key (64-char hex, base64, or Buffer) |
| `legacyKeys` | `(string \| Buffer)[]` | Fallback decryption keys for rotation |
| `hashKey` | `string \| Buffer` | Blind-index HMAC key. Derived from `key` when omitted |

### Methods

- **`addTo(model, fields?)`** — register fields and attach hooks. `fields` is `string[]` or `{ field: { searchable?, hashField? } }`; omit it to auto-discover attributes marked with `encrypt` in the model definition. Chainable.
- **`encrypt(value)`** / **`decrypt(value)`** — manual one-off encryption/decryption using the same format. `decrypt` passes non-encrypted values through.
- **`hash(value)`** — blind-index HMAC (hex) for manual queries.
- **`whereHash(model, field, value)`** — returns `{ [hashField]: hash }` for use in a `where` clause.

### Exports

- `SequelizeEncryption` (also the default export)
- `generateKey()` — random 32-byte key as hex
- `isEncrypted(value)` — checks for the `enc:v1:` payload prefix
- `DecryptionError` — thrown when a payload fails authentication with every configured key (tampering or wrong key)

## Limitations

- Encrypted fields can't appear in `WHERE`, `ORDER BY`, `GROUP BY`, or SQL functions — use blind indexes for equality, and keep non-sensitive columns unencrypted for sorting/filtering.
- `raw: true` results are decrypted at the top level only; nested includes with `raw` are not supported (use regular instances for includes — those are fully supported).
- `Model.upsert()` requires `validate: true` (the default). With `validate: false` the plugin throws rather than silently writing plaintext, because upsert builds its SQL values before any non-validation hook runs.
- Object/array values are encrypted before validation, so custom validators on those fields see ciphertext; validators on string fields are unaffected. Similarly, `bulkCreate(rows, { validate: true })` validates after `beforeBulkCreate` encryption.
- Scoped models (`Model.scope(...)`) share hooks with the base model, but pass the base model to `addTo`.
- Sequelize v6 only; v7 (`@sequelize/core`) support is planned.

## Security notes

- Protects data **at rest**: DB dumps, backups, and direct DB access reveal only ciphertext. It does not protect against a compromised application server, which necessarily holds the key.
- Keep the key out of the database and out of version control. Use a KMS or secret manager.
- Blind indexes intentionally leak equality (identical plaintexts share a hash). Don't mark a field searchable unless you need lookups on it.

## License

MIT
