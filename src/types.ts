export type KeyInput = string | Buffer

export interface EncryptionOptions {
  /** Primary 32-byte key used for encryption and decryption. Accepts a 64-char hex string, base64, or a raw Buffer. */
  key: KeyInput
  /** Previous keys tried in order when the primary key fails to decrypt a value. Enables key rotation. */
  legacyKeys?: KeyInput[]
  /** Separate key for blind-index hashes. Derived from `key` via HKDF when omitted. */
  hashKey?: KeyInput
}

export interface FieldConfig {
  /** Write an HMAC-SHA256 blind index alongside the ciphertext so the value supports exact-match lookups. */
  searchable?: boolean
  /** Column that receives the blind index. Defaults to `<field>Hash`. */
  hashField?: string
}

export type FieldsInput = string[] | Record<string, FieldConfig>

/** Value accepted by the inline `encrypt` attribute option: `true` or a per-field config. */
export type EncryptAttributeOption = boolean | FieldConfig

declare module 'sequelize' {
  interface ModelAttributeColumnOptions {
    /**
     * Mark this attribute for encryption directly in the model definition.
     * Picked up when `addTo(model)` is called without an explicit field list.
     */
    encrypt?: EncryptAttributeOption
  }
}
