import knex from '../database/knex/index.js'

export default class TagsController {
    async index(req, res) {
        const { user_id } = req.params

        const tags = await knex('tags')
                            .distinct('name')
                            .where({ user_id })
                            .orderBy('name')

        res.json(tags)
    }
}