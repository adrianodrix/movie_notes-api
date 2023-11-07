export const up = knex => knex.schema.createTable('notes', table => {
    table.increments('id')
    table.integer('user_id').references('id').inTable('users')
    table.text('title').notNullable()
    table.text('description')
    table.integer('rating')
    table.timestamp('created_at').default(knex.fn.now())
    table.timestamp('updated_at').default(knex.fn.now())
})

export const down = knex => knex.schema.dropTable('notes')