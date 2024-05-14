const express = require('express')

const cors = require('cors')

const mysql = require('mysql')

const app = express()

app.use(cors({
    methods: ['GET', 'PUT', 'POST', 'DELETE', 'OPTIONS']
}))

app.use(express.json())

const db = mysql.createConnection({
    host: 'localhost:8080',
    user: 'root',
    password: '',
    database: 'crud'
})

app.get('/', (req, res) => {
    const sql = 'SELECT * FROM user'

    db.query(sql, (err, data) => {
        if (err) return res.json(err)
        return res.json(data)
    })
})

app.post('/signup', (req, res) => {
    const sql = 'INSERT INTO user (`firstName`, `lastName`, `email`, `password`, `cpf`, `phone`) VALUES (?)'
    const values = [
        req.body.firstName,
        req.body.lastName,
        req.body.email,
        req.body.password,
        req.body.cpf,
        req.body.phone
    ]

    db.query(sql, [values], (err, data) => {
        if (err) return res.json(err)
        return res.json(data)
    })
})

// app.post('/update/:id', (req, res) => {
//     const sql = 'UPDATE user SET name = ?, email = ? WHERE id = ?'
//     const values = [
//         req.body.name,
//         req.body.email
//     ]

//     const id = req.params.id

//     db.query(sql, [...values, id], (err, data) => {
//         if (err) return res.json(err)
//         return res.json(data)
//     })
// })

// app.post('/student/:id', (req, res) => {
//     const sql = 'DELETE FROM user WHERE id = ?'

//     const id = req.params.id

//     db.query(sql, [id], (err, data) => {
//         if (err) return res.json(err)
//         return res.json(data)
//     })
// })

app.listen(8000, () => {
    console.log('Server running...')
})