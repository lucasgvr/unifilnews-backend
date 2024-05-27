const express = require('express')

const cors = require('cors')

const mysql = require('mysql')

const jwt = require('jsonwebtoken')

const bcrypt = require('bcrypt')

const multer = require('multer')

const path = require('path')

const fs = require('fs')

const app = express()

app.use(cors())

app.use(express.json());

app.use(express.static('public'))

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'crud'
})

app.get('/', (request, response) => {
    const sql = 'SELECT * FROM user'

    db.query(sql, (error, data) => {
        if (error) return response.json(error)
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

app.post('/login', async (request, response) => {
    const { email, password } = request.body

    try {
        db.query('SELECT * FROM user WHERE email = ?', [email], async (error, data) => {
            if (error) throw error

            const user = data[0]

            if(!user) {
                return response.status(401).json({ error: 'User not found' });
            }

            const isPasswordValid = await bcrypt.compare(password, user.password);

            if (!isPasswordValid) {
                return response.status(401).json({ error: 'Invalid Credentials' });
            }

            const token = jwt.sign({ userId: user.id }, 'your_jwt_secret', { expiresIn: 10 });

            const updateTokenQuery = 'UPDATE user SET token = ? WHERE id = ?'

            db.query(updateTokenQuery, [token, user.id], (error, data) => {
                if(error) {
                    console.error('Error updating token in database', error)
                    return response.status(500).json({ error: 'Internal server error' })
                }

                response.json({ token, user });
            })
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

app.post('/user/:id', (request, response) => {
    const userId = request.params.id;

    const sql = 'DELETE FROM user WHERE id = ?'

    db.query(sql, [userId], (error, results) => {
        if (error) {
            console.error('Error deleting user:', error)
            return response.status(500).json({ error: 'Internal server error' })
        }

        if (results.affectedRows === 0) {
            return response.status(404).json({ error: 'User not found' })
        }

        return response.status(200).json({ message: 'User deleted successfully' })
    })
})

const storage = multer.diskStorage({
    destination: (request, response, callback) => {
        callback(null, 'public/images')
    },
    filename: (request, file, callback) => {
        callback(null, file.fieldname + '_' + Date.now() + path.extname(file.originalname))
    }
})

const upload = multer({ storage: storage })

app.post('/upload', upload.single('image'), (request, response) => {
    const userId = request.body.id
    const newImage = request.file ? request.file.filename : null

    const getUserImageSql = 'SELECT image FROM user WHERE id = ?'

    db.query(getUserImageSql, [userId], (error, data) => {
        if(error) return response.json({ Message: 'Error retrieving current image' })

        const currentImage = data[0].image

        if(newImage && currentImage) {
            const oldImagePath = path.join(__dirname, 'public/images', currentImage)

            fs.unlink(oldImagePath, (error) => {
                if(error) console.log('Error deleting old image: ', error)
            })
        }
    })

    let sql
    let values

    if(newImage) {
        sql = 'UPDATE user SET firstName = ?, lastName = ?, email = ?, cpf = ?, phone = ?, image = ? WHERE id = ?'
    
        values = [
            request.body.firstName,
            request.body.lastName,
            request.body.email,
            request.body.cpf,
            request.body.phone,
            newImage,
            userId
        ]
    } else {
        sql = 'UPDATE user SET firstName = ?, lastName = ?, email = ?, cpf = ?, phone = ? WHERE id = ?';

        values = [
            request.body.firstName,
            request.body.lastName,
            request.body.email,
            request.body.cpf,
            request.body.phone,
            userId
        ]
    }

    db.query(sql, values, (error, data) => {
        if(error) return response.json({ Message: 'Error' })
        return response.json({ Status: 'Success' })
    })
})

app.post('/user/:id/delete/image', (request, response) => {
    const userId = request.params.id;

    const sql = 'UPDATE user SET image = NULL WHERE id = ?' 

    const getUserImageSql = 'SELECT image FROM user WHERE id = ?'

    db.query(getUserImageSql, [userId], (error, data) => {
        if(error) return response.json({ Message: 'Error retrieving current image' })

        const currentImage = data[0].image

        if(currentImage) {
            const oldImagePath = path.join(__dirname, 'public/images', currentImage)

            fs.unlink(oldImagePath, (error) => {
                if(error) console.log('Error deleting old image: ', error)
            })
        }
    })

    db.query(sql, [userId], (error, data) => {
        if(error) return response.json({ Message: 'Error' })
        return response.json({ Status: 'Success' })
    })
})

app.post('/token', (request, response) => {
    const { token, id } = request.body

    if(token && id) {
      const decodedJwt = JSON.parse(atob(token.split(".")[1]));
      if(decodedJwt.exp * 1000 < Date.now()) {
        return response.json(true)
      } else {
        return response.json(false)
      }
    } else {
        return response.json(true)
    }
})

app.listen(8000, () => {
    console.log('Server running...')
})