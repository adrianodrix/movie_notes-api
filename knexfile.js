import { resolve, dirname } from 'node:path'

export default {
  development: {
    client: 'sqlite3',
    useNullAsDefault: true,
    connection: {
      filename: resolve(dirname(''), 'src', 'database', 'database.db')
    },
    pool: {
      afterCreate: (conn, cb) => conn.run('PRAGMA foreign_keys = ON', cb)
    },
    migrations: {
      directory: resolve(dirname(''), 'src', 'database', 'knex', 'migrations')
    }
  },
}
