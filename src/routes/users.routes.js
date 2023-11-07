import { Router } from "express"
import UsersController from "../controllers/UsersController.js"

const usersRouter = Router()
const usersController = new UsersController()

function myMiddleware(req, res, next) {
    const { isAdmin } = req.body
    if(!isAdmin) {
       return res.status(401).json({ message: "user unauthorized" }) 
    }
    next()
}

// Others methods
usersRouter.get('/', usersController.index)
usersRouter.post('/', myMiddleware, usersController.create)
usersRouter.put('/:id', usersController.update)

export default usersRouter