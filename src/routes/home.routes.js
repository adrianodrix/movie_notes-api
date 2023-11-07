import { Router } from "express"

const homeRouter = Router()


homeRouter.get('/', (req, res) => res.send('Hello World'))

// Route Params. Required
homeRouter.get('/me/:name', (req, res) => {
    const { last_name } = req.query
    const { name } = req.params
    res.send(`Hello! ${name.toLocaleUpperCase()} ${last_name ?? ''}.`)
})

export default homeRouter