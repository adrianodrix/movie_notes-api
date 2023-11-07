import bcrypt from 'bcryptjs'
import AppError from "../utils/AppError.js"
import knex from '../database/knex/index.js'

export default class UsersController {
    
    async create(req, res) {
        const { name, email, password } = req.body

        if(!name) {
            throw new AppError('name is required')
        }

        if(!email) {
            throw new AppError('email is required')
        }

        if(!password) {
            throw new AppError('password is required')
        }

        const checkUserExists = await knex('users').where({ email })
        if (checkUserExists) {    
            throw new AppError(`${email} is already registered.`)
        }

        const hashedPassword = await bcrypt.hash(password, 8)

        await knex('users').insert({
            name, 
            email,
            password: hashedPassword
        })

        res.status(201).json({})
    }

    async update(req, res) {
        const { id } = req.params
        const { name, email, avatar, password, old_password } = req.body

        if(password && !old_password) {
            throw new AppError('You need to enter the old password to set the new password.')
        }

        const user = await knex('users').where({ id })
        if(!user) {
            throw new AppError('User does not exist', 404)
        }

        const userWithUpdatedEmail = await knex('users').where({ email })
        if(userWithUpdatedEmail && userWithUpdatedEmail.id !== user.id) {
            throw new AppError(`${email} is already registered.`)
        }
        
        if(password && old_password) {
            const checkOldPassword = await bcrypt.compare(old_password, user.password)
            if(!checkOldPassword) {
                throw new AppError('the old password does not match')
            }

            user.password = await bcrypt.hash(password, 8)
        }

        user.name = name ?? user.name
        user.email = email ?? user.email
        user.avatar = avatar ?? user.avatar

        await knex('users')
                .where({ id })
                .update(...user)

        return res.json()
    }
}
