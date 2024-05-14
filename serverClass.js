const express = require('express')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
const cors = require('cors')

const User = {
    id: 1,
    username: 'lucas',
    password: 'lucas#'
}

const app = express()

app.use(cors({
    methods: ['GET', 'PUT', 'POST', 'DELETE', 'OPTIONS']
}))

app.use(express.json())

app.post('/api/signin', async (request, response) => {
    const { username, password } = request.body

    try {
        const user = User

        if(!user || password != user.password) {
            return response.status(401).json({ error: 'Invalid Credentials' })
        }

        const token = jwt.sign({ userId: user._id }, 'secret', { expiresIn: '24h' })

        response.json({ token })
    } catch (error) {
        console.log(error)

        response.status(500).json({ error: 'Server Error' })
    }
})

app.listen(3000, () => {
    console.log('Server running...')
})