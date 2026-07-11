import { describe, expect, it } from 'vitest'
import { DecryptionError, generateKey, isEncrypted, SequelizeEncryption } from '../src'

describe('generateKey', () => {
  it('returns a 64-character hex string', () => {
    expect(generateKey()).toMatch(/^[0-9a-f]{64}$/)
  })

  it('returns a different key every time', () => {
    expect(generateKey()).not.toBe(generateKey())
  })
})

describe('key parsing', () => {
  it('accepts hex, base64 and Buffer keys', () => {
    const raw = Buffer.alloc(32, 7)
    const fromHex = new SequelizeEncryption({ key: raw.toString('hex') })
    const fromBase64 = new SequelizeEncryption({ key: raw.toString('base64') })
    const fromBuffer = new SequelizeEncryption({ key: raw })

    const payload = fromHex.encrypt('hello')
    expect(fromBase64.decrypt(payload)).toBe('hello')
    expect(fromBuffer.decrypt(payload)).toBe('hello')
  })

  it('rejects keys of the wrong length', () => {
    expect(() => new SequelizeEncryption({ key: 'abcd' })).toThrow(/32-byte/)
    expect(() => new SequelizeEncryption({ key: Buffer.alloc(16) })).toThrow(/32 bytes/)
  })
})

describe('encrypt / decrypt', () => {
  const enc = new SequelizeEncryption({ key: generateKey() })

  it('round-trips strings, numbers, booleans and objects', () => {
    for (const value of ['secret', 42, true, { nested: ['a', 1] }]) {
      expect(enc.decrypt(enc.encrypt(value))).toEqual(value)
    }
  })

  it('produces a fresh IV per call', () => {
    expect(enc.encrypt('same')).not.toBe(enc.encrypt('same'))
  })

  it('marks payloads with the enc:v1: prefix', () => {
    const payload = enc.encrypt('secret')
    expect(payload.startsWith('enc:v1:')).toBe(true)
    expect(isEncrypted(payload)).toBe(true)
    expect(isEncrypted('plain text')).toBe(false)
  })

  it('does not double-encrypt an already encrypted payload', () => {
    const payload = enc.encrypt('secret')
    expect(enc.encrypt(payload)).toBe(payload)
  })

  it('passes non-encrypted values through decrypt unchanged', () => {
    expect(enc.decrypt('plain text')).toBe('plain text')
    expect(enc.decrypt(null)).toBeNull()
    expect(enc.decrypt(7)).toBe(7)
  })

  it('rejects null and undefined for encrypt', () => {
    expect(() => enc.encrypt(null)).toThrow()
    expect(() => enc.encrypt(undefined)).toThrow()
  })

  it('throws DecryptionError on tampered payloads', () => {
    const payload = enc.encrypt('secret')
    const tampered = payload.slice(0, -4) + (payload.endsWith('AAAA') ? 'BBBB' : 'AAAA')
    expect(() => enc.decrypt(tampered)).toThrow(DecryptionError)
  })

  it('throws DecryptionError with the wrong key', () => {
    const other = new SequelizeEncryption({ key: generateKey() })
    expect(() => other.decrypt(enc.encrypt('secret'))).toThrow(DecryptionError)
  })
})

describe('key rotation', () => {
  it('decrypts old payloads via legacyKeys and encrypts with the new key', () => {
    const oldKey = generateKey()
    const newKey = generateKey()
    const oldEnc = new SequelizeEncryption({ key: oldKey })
    const rotated = new SequelizeEncryption({ key: newKey, legacyKeys: [oldKey] })

    const oldPayload = oldEnc.encrypt('legacy secret')
    expect(rotated.decrypt(oldPayload)).toBe('legacy secret')

    const reEncrypted = rotated.encrypt(rotated.decrypt(oldPayload))
    expect(() => oldEnc.decrypt(reEncrypted)).toThrow(DecryptionError)
    expect(rotated.decrypt(reEncrypted)).toBe('legacy secret')
  })
})

describe('hash', () => {
  it('is deterministic per key and differs across keys', () => {
    const a = new SequelizeEncryption({ key: generateKey() })
    const b = new SequelizeEncryption({ key: generateKey() })
    expect(a.hash('user@example.com')).toBe(a.hash('user@example.com'))
    expect(a.hash('user@example.com')).not.toBe(b.hash('user@example.com'))
    expect(a.hash('user@example.com')).toMatch(/^[0-9a-f]{64}$/)
  })

  it('stays stable when hashKey is pinned while the main key rotates', () => {
    const hashKey = generateKey()
    const a = new SequelizeEncryption({ key: generateKey(), hashKey })
    const b = new SequelizeEncryption({ key: generateKey(), hashKey })
    expect(a.hash('user@example.com')).toBe(b.hash('user@example.com'))
  })
})
