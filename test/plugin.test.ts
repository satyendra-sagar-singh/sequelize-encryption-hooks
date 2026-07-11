import { DataTypes, Model, QueryTypes, Sequelize } from 'sequelize'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { generateKey, isEncrypted, SequelizeEncryption } from '../src'

const key = generateKey()
const enc = new SequelizeEncryption({ key })
const sequelize = new Sequelize({ dialect: 'sqlite', storage: ':memory:', logging: false })

class User extends Model {
  declare id: number
  declare name: string
  declare email: string | null
  declare emailHash: string | null
  declare ssn: string | null
  declare profile: Record<string, unknown> | null
}

class Note extends Model {
  declare id: number
  declare body: string | null
  declare userId: number
}

beforeAll(async () => {
  User.init(
    {
      name: { type: DataTypes.STRING, allowNull: false },
      email: DataTypes.TEXT,
      emailHash: DataTypes.STRING,
      ssn: DataTypes.TEXT,
      profile: DataTypes.TEXT,
    },
    { sequelize, modelName: 'user' },
  )
  Note.init({ body: DataTypes.TEXT }, { sequelize, modelName: 'note' })
  User.hasMany(Note)
  Note.belongsTo(User)

  enc.addTo(User, { email: { searchable: true }, ssn: {}, profile: {} })
  enc.addTo(Note, ['body'])

  await sequelize.sync()
})

afterAll(async () => {
  await sequelize.close()
})

beforeEach(async () => {
  await Note.destroy({ where: {} })
  await User.destroy({ where: {} })
})

async function rawRow(table: string, id: number): Promise<Record<string, unknown>> {
  const rows = await sequelize.query(`SELECT * FROM ${table} WHERE id = :id`, {
    type: QueryTypes.SELECT,
    replacements: { id },
  })
  return rows[0] as Record<string, unknown>
}

describe('create', () => {
  it('stores ciphertext in the database but keeps plaintext on the instance', async () => {
    const user = await User.create({ name: 'Ada', email: 'ada@example.com', ssn: '123-45-6789' })

    expect(user.email).toBe('ada@example.com')
    expect(user.ssn).toBe('123-45-6789')

    const row = await rawRow('users', user.id)
    expect(isEncrypted(row.email)).toBe(true)
    expect(isEncrypted(row.ssn)).toBe(true)
    expect(row.emailHash).toBe(enc.hash('ada@example.com'))
    expect(row.name).toBe('Ada')
  })

  it('leaves null values untouched', async () => {
    const user = await User.create({ name: 'NoData' })
    const row = await rawRow('users', user.id)
    expect(row.email).toBeNull()
    expect(row.emailHash).toBeNull()
    expect(row.ssn).toBeNull()
  })

  it('round-trips non-string values', async () => {
    const profile = { plan: 'pro', limits: { seats: 5 } }
    const user = await User.create({ name: 'Obj', profile })
    expect(user.profile).toEqual(profile)

    const found = await User.findByPk(user.id)
    expect(found!.profile).toEqual(profile)
  })

  it('saves unrelated changes without touching an unchanged object field', async () => {
    const profile = { plan: 'pro' }
    const created = await User.create({ name: 'Obj', profile })

    const found = await User.findByPk(created.id)
    found!.name = 'Renamed'
    await found!.save()

    const reloaded = await User.findByPk(created.id)
    expect(reloaded!.name).toBe('Renamed')
    expect(reloaded!.profile).toEqual(profile)
  })
})

describe('find', () => {
  it('decrypts findByPk / findOne / findAll results', async () => {
    const created = await User.create({ name: 'Ada', ssn: '111' })
    await User.create({ name: 'Grace', ssn: '222' })

    const byPk = await User.findByPk(created.id)
    expect(byPk!.ssn).toBe('111')

    const one = await User.findOne({ where: { name: 'Grace' } })
    expect(one!.ssn).toBe('222')

    const all = await User.findAll({ order: [['id', 'ASC']] })
    expect(all.map(u => u.ssn)).toEqual(['111', '222'])
  })

  it('does not leave decrypted fields marked as changed', async () => {
    const created = await User.create({ name: 'Ada', ssn: '111' })
    const found = await User.findByPk(created.id)
    expect(found!.changed()).toBe(false)
  })

  it('decrypts raw query results at the top level', async () => {
    await User.create({ name: 'Ada', ssn: '111' })
    const rows = await User.findAll({ raw: true })
    expect((rows[0] as unknown as { ssn: string }).ssn).toBe('111')
  })

  it('decrypts included associations', async () => {
    const user = await User.create({ name: 'Ada', ssn: '111' })
    await Note.create({ body: 'launch codes', userId: user.id })

    const withNotes = await User.findAll({ include: Note })
    const notes = withNotes[0].get('notes') as Note[]
    expect(notes[0].body).toBe('launch codes')

    const noteRow = await rawRow('notes', notes[0].id)
    expect(isEncrypted(noteRow.body)).toBe(true)

    const withUser = await Note.findOne({ include: User })
    expect((withUser!.get('user') as User).ssn).toBe('111')
  })

  it('returns pre-existing plaintext rows unchanged (migration mode)', async () => {
    await sequelize.query(
      `INSERT INTO users (name, ssn, createdAt, updatedAt) VALUES ('legacy', '999-99-9999', datetime('now'), datetime('now'))`,
    )
    const user = await User.findOne({ where: { name: 'legacy' } })
    expect(user!.ssn).toBe('999-99-9999')
  })
})

describe('update', () => {
  it('encrypts instance.save() updates and restores plaintext after', async () => {
    const user = await User.create({ name: 'Ada', ssn: '111' })
    user.ssn = '333'
    await user.save()

    expect(user.ssn).toBe('333')
    const row = await rawRow('users', user.id)
    expect(isEncrypted(row.ssn)).toBe(true)
    expect(enc.decrypt(row.ssn)).toBe('333')
  })

  it('encrypts bulk Model.update() and refreshes the blind index', async () => {
    const user = await User.create({ name: 'Ada', email: 'old@example.com' })
    await User.update({ email: 'new@example.com' }, { where: { id: user.id } })

    const row = await rawRow('users', user.id)
    expect(isEncrypted(row.email)).toBe(true)
    expect(enc.decrypt(row.email)).toBe('new@example.com')
    expect(row.emailHash).toBe(enc.hash('new@example.com'))
  })

  it('does not double-encrypt with individualHooks: true', async () => {
    const user = await User.create({ name: 'Ada', ssn: '111' })
    await User.update({ ssn: '444' }, { where: { id: user.id }, individualHooks: true })

    const row = await rawRow('users', user.id)
    expect(enc.decrypt(row.ssn)).toBe('444')

    const found = await User.findByPk(user.id)
    expect(found!.ssn).toBe('444')
  })

  it('encrypts object values in bulk Model.update()', async () => {
    const user = await User.create({ name: 'Obj', profile: { plan: 'free' } })
    await User.update({ profile: { plan: 'pro' } }, { where: { id: user.id } })

    const row = await rawRow('users', user.id)
    expect(isEncrypted(row.profile)).toBe(true)
    expect(enc.decrypt(row.profile)).toEqual({ plan: 'pro' })
  })

  it('clears the blind index when the value is set to null', async () => {
    const user = await User.create({ name: 'Ada', email: 'ada@example.com' })
    await User.update({ email: null }, { where: { id: user.id } })

    const row = await rawRow('users', user.id)
    expect(row.email).toBeNull()
    expect(row.emailHash).toBeNull()
  })
})

describe('bulkCreate', () => {
  it('encrypts every instance and returns plaintext instances', async () => {
    const users = await User.bulkCreate([
      { name: 'Ada', ssn: '111' },
      { name: 'Grace', ssn: '222' },
    ])
    expect(users.map(u => u.ssn)).toEqual(['111', '222'])

    for (const user of users) {
      const row = await rawRow('users', user.id)
      expect(isEncrypted(row.ssn)).toBe(true)
    }
  })
})

describe('upsert', () => {
  it('encrypts on insert and update paths', async () => {
    const [inserted] = await User.upsert({ id: 9001, name: 'Ada', ssn: '111', email: 'ada@example.com' })
    expect(inserted.ssn).toBe('111')

    let row = await rawRow('users', 9001)
    expect(isEncrypted(row.ssn)).toBe(true)
    expect(row.emailHash).toBe(enc.hash('ada@example.com'))

    await User.upsert({ id: 9001, name: 'Ada', ssn: '555', email: 'ada2@example.com' })
    row = await rawRow('users', 9001)
    expect(enc.decrypt(row.ssn)).toBe('555')
    expect(row.emailHash).toBe(enc.hash('ada2@example.com'))

    const found = await User.findByPk(9001)
    expect(found!.ssn).toBe('555')
    expect(found!.email).toBe('ada2@example.com')
  })

  it('rejects upsert with validate: false instead of leaking plaintext', async () => {
    await expect(User.upsert({ id: 9002, name: 'Ada', ssn: '111' }, { validate: false })).rejects.toThrow(
      /validate: false/,
    )
  })
})

describe('blind index lookups', () => {
  it('finds rows by encrypted value via whereHash', async () => {
    await User.create({ name: 'Ada', email: 'ada@example.com' })
    await User.create({ name: 'Grace', email: 'grace@example.com' })

    const found = await User.findOne({ where: enc.whereHash(User, 'email', 'grace@example.com') })
    expect(found!.name).toBe('Grace')
    expect(found!.email).toBe('grace@example.com')
  })

  it('rejects whereHash on non-searchable fields', () => {
    expect(() => enc.whereHash(User, 'ssn', '111')).toThrow(/not a searchable/)
  })
})

describe('inline encrypt markers', () => {
  class Doc extends Model {
    declare id: number
    declare title: string
    declare body: string | null
    declare owner: string | null
    declare ownerHash: string | null
  }

  beforeAll(async () => {
    Doc.init(
      {
        title: DataTypes.STRING,
        body: { type: DataTypes.TEXT, encrypt: true },
        owner: { type: DataTypes.TEXT, encrypt: { searchable: true, hashField: 'ownerHash' } },
        ownerHash: DataTypes.STRING,
      },
      { sequelize, modelName: 'doc' },
    )
    enc.addTo(Doc)
    await Doc.sync()
  })

  it('encrypts only the marked fields and leaves the rest plaintext', async () => {
    const doc = await Doc.create({ title: 'Public title', body: 'private body', owner: 'ada' })

    const row = await rawRow('docs', doc.id)
    expect(row.title).toBe('Public title')
    expect(isEncrypted(row.body)).toBe(true)
    expect(isEncrypted(row.owner)).toBe(true)
    expect(row.ownerHash).toBe(enc.hash('ada'))

    const found = await Doc.findByPk(doc.id)
    expect(found!.title).toBe('Public title')
    expect(found!.body).toBe('private body')
    expect(found!.owner).toBe('ada')
  })

  it('supports whereHash on marker-configured searchable fields', async () => {
    await Doc.create({ title: 'findable', owner: 'grace' })
    const found = await Doc.findOne({ where: enc.whereHash(Doc, 'owner', 'grace') })
    expect(found!.title).toBe('findable')
  })

  it('throws when nothing is marked and no field list is passed', () => {
    class Plain extends Model {}
    Plain.init({ label: DataTypes.STRING }, { sequelize, modelName: 'plain1' })
    expect(() => enc.addTo(Plain)).toThrow(/marked/)
  })
})

describe('configuration validation', () => {
  it('rejects unknown attributes', () => {
    class Fresh extends Model {}
    Fresh.init({ label: DataTypes.STRING }, { sequelize, modelName: 'fresh1' })
    expect(() => enc.addTo(Fresh, ['nope'])).toThrow(/does not exist/)
  })

  it('rejects searchable fields without a hash column', () => {
    class Fresh extends Model {}
    Fresh.init({ secret: DataTypes.TEXT }, { sequelize, modelName: 'fresh2' })
    expect(() => enc.addTo(Fresh, { secret: { searchable: true } })).toThrow(/secretHash/)
  })

  it('rejects registering the same model twice', () => {
    expect(() => enc.addTo(User, ['ssn'])).toThrow(/already added/)
  })
})
