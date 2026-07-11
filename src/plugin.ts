import type { FindOptions, Includeable, Model, ModelStatic } from 'sequelize'
import {
  DecryptionError,
  decryptValue,
  deriveHashKey,
  encryptValue,
  hmacValue,
  isEncrypted,
  parseKey,
} from './crypto'
import type { EncryptionOptions, FieldConfig, FieldsInput } from './types'

type AnyModel = ModelStatic<Model>

interface ResolvedField {
  hashField: string | null
}

interface InstanceInternals {
  dataValues: Record<string, unknown>
  _previousDataValues: Record<string, unknown>
}

interface WriteOptions {
  fields?: string[]
}

interface Hookable {
  addHook(name: string, fn: (...args: any[]) => unknown): unknown
}

function isModelInstance(value: unknown): value is Model {
  return typeof (value as Model | null)?.getDataValue === 'function'
}

function includeInWrite(options: WriteOptions | undefined, field: string): void {
  if (!options || !Array.isArray(options.fields)) return
  if (!options.fields.includes(field)) options.fields.push(field)
}

export class SequelizeEncryption {
  private readonly key: Buffer
  private readonly decryptionKeys: Buffer[]
  private readonly hashKey: Buffer
  private readonly models = new Map<AnyModel, Map<string, ResolvedField>>()

  constructor(options: EncryptionOptions) {
    this.key = parseKey(options.key, 'key')
    this.decryptionKeys = [
      this.key,
      ...(options.legacyKeys ?? []).map((legacyKey, index) => parseKey(legacyKey, `legacyKeys[${index}]`)),
    ]
    this.hashKey = options.hashKey ? parseKey(options.hashKey, 'hashKey') : deriveHashKey(this.key)
  }

  /**
   * Register encrypted fields on a model and attach the encrypt/decrypt lifecycle hooks.
   * Pass an explicit field list, or omit `fields` to pick up attributes marked with
   * `encrypt: true | { ... }` in the model definition.
   */
  addTo(model: AnyModel, fields?: FieldsInput): this {
    if (this.models.has(model)) {
      throw new Error(`Encryption hooks already added to model "${model.name}"`)
    }
    this.models.set(model, this.resolveFields(model, fields))
    this.attachHooks(model)
    return this
  }

  /** Encrypt a single value into the portable `enc:v1:` payload format. */
  encrypt(value: unknown): string {
    if (value === null || value === undefined) {
      throw new Error('Cannot encrypt null or undefined')
    }
    if (isEncrypted(value)) return value
    return encryptValue(JSON.stringify(value), this.key)
  }

  /** Decrypt an `enc:v1:` payload. Non-encrypted values pass through unchanged. */
  decrypt(value: unknown): unknown {
    if (!isEncrypted(value)) return value
    return JSON.parse(decryptValue(value, this.decryptionKeys))
  }

  /** Compute the blind-index hash for a value — use in WHERE clauses against the hash column. */
  hash(value: unknown): string {
    const canonical = typeof value === 'string' ? value : JSON.stringify(value)
    return hmacValue(canonical, this.hashKey)
  }

  /** Build a WHERE fragment for an exact-match lookup on a searchable encrypted field. */
  whereHash(model: AnyModel, field: string, value: unknown): Record<string, string> {
    const hashField = this.models.get(model)?.get(field)?.hashField
    if (!hashField) {
      throw new Error(`"${field}" is not a searchable encrypted field on model "${model.name}"`)
    }
    return { [hashField]: this.hash(value) }
  }

  private resolveFields(model: AnyModel, fields: FieldsInput | undefined): Map<string, ResolvedField> {
    const attributes = (model as unknown as { rawAttributes: Record<string, unknown> }).rawAttributes
    const entries: Array<[string, FieldConfig]> =
      fields === undefined
        ? this.discoverMarkedFields(attributes)
        : Array.isArray(fields)
          ? fields.map(field => [field, {}])
          : Object.entries(fields)
    if (entries.length === 0) {
      throw new Error(
        fields === undefined
          ? `No attributes on model "${model.name}" are marked with \`encrypt\` — mark fields in the model definition or pass them to addTo()`
          : `No encrypted fields configured for model "${model.name}"`,
      )
    }
    const resolved = new Map<string, ResolvedField>()
    for (const [field, config] of entries) {
      if (!attributes[field]) {
        throw new Error(`Attribute "${field}" does not exist on model "${model.name}"`)
      }
      const hashField = config.searchable ? (config.hashField ?? `${field}Hash`) : null
      if (hashField && !attributes[hashField]) {
        throw new Error(
          `Blind-index column "${hashField}" for "${model.name}.${field}" is not defined on the model — add it as a STRING attribute`,
        )
      }
      resolved.set(field, { hashField })
    }
    return resolved
  }

  private discoverMarkedFields(attributes: Record<string, unknown>): Array<[string, FieldConfig]> {
    const entries: Array<[string, FieldConfig]> = []
    for (const [name, attribute] of Object.entries(attributes)) {
      const marker = (attribute as { encrypt?: boolean | FieldConfig }).encrypt
      if (!marker) continue
      entries.push([name, marker === true ? {} : marker])
    }
    return entries
  }

  private attachHooks(model: AnyModel): void {
    const hooks = model as unknown as Hookable
    // Objects/arrays must be encrypted before validation runs: Sequelize's built-in
    // "string violation" check rejects them on STRING/TEXT columns.
    hooks.addHook('beforeValidate', (instance: Model, options?: WriteOptions) =>
      this.encryptObjectValues(model, instance, options),
    )
    // Upsert computes its insert/update values right after validate() and before
    // beforeUpsert, so validation is the only hook where encryption can land.
    hooks.addHook('afterValidate', (instance: Model, options?: WriteOptions & { instance?: Model }) => {
      if (options?.instance === instance) this.encryptInstance(model, instance, options, false)
    })
    hooks.addHook('beforeCreate', (instance: Model, options?: WriteOptions) =>
      this.encryptInstance(model, instance, options, false),
    )
    hooks.addHook('beforeUpdate', (instance: Model, options?: WriteOptions) =>
      this.encryptInstance(model, instance, options, true),
    )
    hooks.addHook(
      'beforeBulkCreate',
      (instances: Model[], options?: WriteOptions & { updateOnDuplicate?: string[] }) => {
        for (const instance of instances) this.encryptInstance(model, instance, options, false)
        this.extendUpdateOnDuplicate(model, options)
      },
    )
    hooks.addHook('beforeBulkUpdate', (options: WriteOptions & { attributes?: Record<string, unknown> }) => {
      if (options?.attributes) this.encryptPlainObject(model, options.attributes, options)
    })
    hooks.addHook('beforeUpsert', (values: Record<string, unknown>, options: { instance?: Model }) =>
      this.assertUpsertEncrypted(model, options),
    )
    hooks.addHook('afterCreate', (instance: Model) => this.decryptOwnFields(model, instance))
    hooks.addHook('afterUpdate', (instance: Model) => this.decryptOwnFields(model, instance))
    hooks.addHook('afterBulkCreate', (instances: Model[]) => {
      for (const instance of instances) this.decryptOwnFields(model, instance)
    })
    hooks.addHook('afterUpsert', (result: [Model | null, boolean | null]) => {
      if (result?.[0]) this.decryptOwnFields(model, result[0])
    })
    hooks.addHook('afterFind', (result: Model | Model[] | null, options?: FindOptions) =>
      this.decryptFindResult(model, result, options),
    )
  }

  private encryptInstance(
    model: AnyModel,
    instance: Model,
    options: WriteOptions | undefined,
    onlyPersistedFields: boolean,
  ): void {
    const fields = this.models.get(model)
    if (!fields) return
    for (const [field, { hashField }] of fields) {
      if (onlyPersistedFields && !this.willPersist(instance, field, options)) continue
      const value = instance.getDataValue(field)
      if (value === undefined || isEncrypted(value)) continue
      if (value === null) {
        if (hashField) {
          instance.setDataValue(hashField, null)
          includeInWrite(options, hashField)
        }
        continue
      }
      if (hashField) {
        instance.setDataValue(hashField, this.hash(value))
        includeInWrite(options, hashField)
      }
      instance.setDataValue(field, this.encrypt(value))
    }
  }

  private willPersist(instance: Model, field: string, options: WriteOptions | undefined): boolean {
    if (instance.changed(field as never) === true) return true
    return Array.isArray(options?.fields) && options.fields.includes(field)
  }

  private encryptPlainObject(model: AnyModel, values: Record<string, unknown>, options?: WriteOptions): void {
    const fields = this.models.get(model)
    if (!fields) return
    for (const [field, { hashField }] of fields) {
      if (!(field in values) || values[field] === undefined) continue
      const value = values[field]
      if (isEncrypted(value)) continue
      if (value === null) {
        if (hashField) {
          values[hashField] = null
          includeInWrite(options, hashField)
        }
        continue
      }
      if (hashField) {
        values[hashField] = this.hash(value)
        includeInWrite(options, hashField)
      }
      values[field] = this.encrypt(value)
    }
  }

  private encryptObjectValues(model: AnyModel, instance: Model, options: WriteOptions | undefined): void {
    const fields = this.models.get(model)
    if (!fields) return
    for (const [field, { hashField }] of fields) {
      const value = instance.getDataValue(field)
      if (value === null || value === undefined || typeof value !== 'object') continue
      if (instance.isNewRecord || this.willPersist(instance, field, options)) {
        if (hashField) {
          instance.setDataValue(hashField, this.hash(value))
          includeInWrite(options, hashField)
        }
        instance.setDataValue(field, this.encrypt(value))
        continue
      }
      // Unchanged object (decrypted earlier by a find): swap in ciphertext so validation
      // passes, without marking the field changed — it won't be re-written to the DB.
      ;(instance as unknown as InstanceInternals).dataValues[field] = this.encrypt(value)
    }
  }

  private assertUpsertEncrypted(model: AnyModel, options: { instance?: Model } | undefined): void {
    const fields = this.models.get(model)
    const instance = options?.instance
    if (!fields || !instance) return
    for (const field of fields.keys()) {
      const value = instance.getDataValue(field)
      if (value !== null && value !== undefined && !isEncrypted(value)) {
        throw new Error(
          `Cannot upsert encrypted field "${model.name}.${field}" with validate: false — upsert encryption runs during validation`,
        )
      }
    }
  }

  private extendUpdateOnDuplicate(model: AnyModel, options?: { updateOnDuplicate?: string[] }): void {
    if (!options || !Array.isArray(options.updateOnDuplicate)) return
    const fields = this.models.get(model)
    if (!fields) return
    for (const [field, { hashField }] of fields) {
      if (hashField && options.updateOnDuplicate.includes(field) && !options.updateOnDuplicate.includes(hashField)) {
        options.updateOnDuplicate.push(hashField)
      }
    }
  }

  private decryptFindResult(model: AnyModel, result: Model | Model[] | null, options?: FindOptions): void {
    if (!result) return
    for (const item of Array.isArray(result) ? result : [result]) {
      if (!item) continue
      this.decryptOwnFields(model, item)
      this.decryptIncluded(item, options?.include)
    }
  }

  private decryptOwnFields(model: AnyModel, target: unknown): void {
    const fields = this.models.get(model)
    if (!fields || !target || typeof target !== 'object') return
    const instance = isModelInstance(target) ? (target as unknown as InstanceInternals) : null
    const container = instance ? instance.dataValues : (target as Record<string, unknown>)
    for (const field of fields.keys()) {
      const value = container[field]
      if (!isEncrypted(value)) continue
      let plaintext: unknown
      try {
        plaintext = this.decrypt(value)
      } catch (error) {
        throw new DecryptionError(`Failed to decrypt "${model.name}.${field}"`, { cause: error })
      }
      container[field] = plaintext
      // Keep _previousDataValues in sync so changed() stays false for values we decrypted.
      if (instance) instance._previousDataValues[field] = plaintext
    }
  }

  private decryptIncluded(item: unknown, includes: Includeable | Includeable[] | undefined): void {
    if (!includes || !isModelInstance(item)) return
    for (const include of Array.isArray(includes) ? includes : [includes]) {
      if (typeof include !== 'object' || include === null) continue
      const { model: includedModel, as, include: nestedIncludes } = include as {
        model?: AnyModel
        as?: string
        include?: Includeable[]
      }
      if (!includedModel || !as) continue
      const nested = (item as unknown as InstanceInternals).dataValues[as]
      if (!nested) continue
      for (const nestedItem of Array.isArray(nested) ? nested : [nested]) {
        if (this.models.has(includedModel)) this.decryptOwnFields(includedModel, nestedItem)
        this.decryptIncluded(nestedItem, nestedIncludes)
      }
    }
  }
}
