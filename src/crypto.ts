import { createCipheriv, createDecipheriv, createHmac, hkdfSync, randomBytes } from 'node:crypto'
import type { KeyInput } from './types'

const PAYLOAD_PREFIX = 'enc:v1:'
const ALGORITHM = 'aes-256-gcm'
const IV_LENGTH = 12
const AUTH_TAG_LENGTH = 16
const KEY_LENGTH = 32
const HKDF_INFO = 'sequelize-encryption-hooks/blind-index'
const HEX_KEY_PATTERN = /^[0-9a-f]{64}$/i

export class DecryptionError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options)
    this.name = 'DecryptionError'
  }
}

export function isEncrypted(value: unknown): value is string {
  return typeof value === 'string' && value.startsWith(PAYLOAD_PREFIX)
}

export function generateKey(): string {
  return randomBytes(KEY_LENGTH).toString('hex')
}

export function parseKey(input: KeyInput, name: string): Buffer {
  if (Buffer.isBuffer(input)) {
    if (input.length !== KEY_LENGTH) {
      throw new Error(`"${name}" must be exactly ${KEY_LENGTH} bytes, got ${input.length}`)
    }
    return Buffer.from(input)
  }
  if (typeof input === 'string') {
    if (HEX_KEY_PATTERN.test(input)) {
      return Buffer.from(input, 'hex')
    }
    const decoded = Buffer.from(input, 'base64')
    if (decoded.length === KEY_LENGTH) {
      return decoded
    }
  }
  throw new Error(
    `"${name}" must be a ${KEY_LENGTH}-byte Buffer, a ${KEY_LENGTH * 2}-character hex string, or a base64-encoded ${KEY_LENGTH}-byte key`,
  )
}

export function deriveHashKey(key: Buffer): Buffer {
  return Buffer.from(hkdfSync('sha256', key, Buffer.alloc(0), HKDF_INFO, KEY_LENGTH))
}

export function encryptValue(plaintext: string, key: Buffer): string {
  const iv = randomBytes(IV_LENGTH)
  const cipher = createCipheriv(ALGORITHM, key, iv)
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])
  const authTag = cipher.getAuthTag()
  return `${PAYLOAD_PREFIX}${iv.toString('base64')}:${authTag.toString('base64')}:${ciphertext.toString('base64')}`
}

export function decryptValue(payload: string, keys: Buffer[]): string {
  const parts = payload.slice(PAYLOAD_PREFIX.length).split(':')
  if (parts.length !== 3) {
    throw new DecryptionError('Malformed encrypted payload')
  }
  const [iv, authTag, ciphertext] = parts.map(part => Buffer.from(part, 'base64'))
  if (iv.length !== IV_LENGTH || authTag.length !== AUTH_TAG_LENGTH) {
    throw new DecryptionError('Malformed encrypted payload')
  }
  let lastError: unknown
  for (const key of keys) {
    try {
      const decipher = createDecipheriv(ALGORITHM, key, iv)
      decipher.setAuthTag(authTag)
      return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8')
    } catch (error) {
      lastError = error
    }
  }
  throw new DecryptionError('Unable to decrypt payload with any configured key', { cause: lastError })
}

export function hmacValue(value: string, key: Buffer): string {
  return createHmac('sha256', key).update(value).digest('hex')
}
