# Contributing

Thanks for your interest in improving `sequelize-encryption-hooks`!

## Getting started

```bash
git clone https://github.com/satyendra-sagar-singh/sequelize-encryption-hooks.git
cd sequelize-encryption-hooks
nvm use        # Node version from .nvmrc
npm install
```

## Development workflow

| Command | What it does |
| --- | --- |
| `npm test` | Run the test suite (vitest + in-memory SQLite) |
| `npm run test:watch` | Tests in watch mode |
| `npm run test:coverage` | Tests with coverage thresholds enforced |
| `npm run typecheck` | Strict TypeScript check |
| `npm run build` | Build ESM + CJS + type declarations with tsup |
| `npm run check:package` | Validate the publishable package (publint + arethetypeswrong) |

## Guidelines

- **Every behavior change needs a test.** Tests run against a real (in-memory) SQLite database — assert on raw rows to prove ciphertext is actually stored, not just that instances look right.
- **Watch the write paths.** The riskiest bugs in this package are Sequelize write paths that bypass encryption. If you touch hook logic, check `create`, `save`, `Model.update`, `bulkCreate`, and `upsert` — including `individualHooks` and `validate: false` variants.
- Keep the public API surface small and typed; avoid new runtime dependencies.
- CI must pass (typecheck, tests with coverage, build, package checks) on Node 18-24.

## Reporting bugs and requesting features

Use the [issue templates](https://github.com/satyendra-sagar-singh/sequelize-encryption-hooks/issues/new/choose). For security vulnerabilities, **do not open a public issue** — see [SECURITY.md](SECURITY.md).

## Releases

Maintainers: bump the version in package.json, update CHANGELOG.md, commit, then tag and push:

```bash
git tag v0.x.y && git push origin main v0.x.y
```

The publish workflow builds, validates, and publishes to npm via trusted publishing.
