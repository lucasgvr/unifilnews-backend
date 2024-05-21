const express = require('express')

const cors = require('cors')

const mysql = require('mysql')

const jwt = require('jsonwebtoken')

const bcrypt = require('bcrypt');

const app = express()

app.use(cors({
    methods: ['GET', 'PUT', 'POST', 'DELETE', 'OPTIONS']
}))

app.use(express.json())

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'crud'
})

app.get('/', (request, response) => {
    const sql = 'SELECT * FROM user'

    db.query(sql, (error, data) => {
        if (error) return response.json(err)
        return response.json(data)
    })
})

app.post('/signup', async (request, response) => {
    const sql = 'INSERT INTO user (`firstName`, `lastName`, `email`, `password`, `cpf`, `phone`) VALUES (?)'

    const hashedPassword = await bcrypt.hash(request.body.password, 10);

    const values = [
        request.body.firstName,
        request.body.lastName,
        request.body.email,
        hashedPassword,
        request.body.cpf,
        request.body.phone
    ]

    db.query(sql, [values], (error, data) => {
        if (error) return response.json(error)
        return response.json(data)
    })
})

app.post('/signin', async (request, response) => {
    const { email, password } = request.body

    try {
        db.query('SELECT * FROM user WHERE email = ?', [email], async (error, data) => {
            if (error) throw error

            const user = data[0]

            if(!user) {
                return response.status(401).json({ error: 'Invalid Credentials' });
            }

            const isPasswordValid = await bcrypt.compare(password, user.password);

            if (!isPasswordValid) {
                return response.status(401).json({ error: 'Invalid Credentials' });
            }

            const token = jwt.sign({ userId: user.id }, 'your_jwt_secret', { expiresIn: '24h' });

            response.json({ token, user });
        })
    } catch (error) {
        console.log(error)

        response.status(500).json({ error: 'Server Error' })
    }
})

app.get('/user', (request, response) => {
    const userId = request.query.id

    const sql = 'SELECT * FROM user WHERE id = ?'

    db.query(sql, [userId], (error, data) => {
        if(error) {
            return response.status(500).send(error)
        }

        if(data.length > 0) {
            response.send({ user: data[0] })
        } else {
            response.status(400).send({ error: 'User not found' })
        }
    })
})

app.listen(8000, () => {
    console.log('Server running...')
})