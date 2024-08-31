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

            const token = jwt.sign({ userId: user.id }, 'your_jwt_secret', { expiresIn: '24h' });

            const updateTokenQuery = 'UPDATE user SET token = ? WHERE id = ?'

            db.query(updateTokenQuery, [token, user.id], (error, data) => {
                if(error) {
                    console.error('Error updating token in database', error)
                    return response.status(500).json({ error: 'Internal server error' })
                }

                response.json({ token, user, Status: 'Signed' });
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

app.post('/upload', upload.single('image'), async (request, response) => {
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
    let hashedPassword

    if(request.body.newPassword === 'true') {
        hashedPassword = await bcrypt.hash(request.body.password, 10);
    } else {
        hashedPassword = request.body.password
    }

    if(newImage) {
        sql = 'UPDATE user SET firstName = ?, lastName = ?, email = ?, password = ?, cpf = ?, phone = ?, image = ? WHERE id = ?'
    
        values = [
            request.body.firstName,
            request.body.lastName,
            request.body.email,
            hashedPassword,
            request.body.cpf,
            request.body.phone,
            newImage,
            userId
        ]
    } else {
        sql = 'UPDATE user SET firstName = ?, lastName = ?, email = ?, password = ?, cpf = ?, phone = ? WHERE id = ?';

        values = [
            request.body.firstName,
            request.body.lastName,
            request.body.email,
            hashedPassword,
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
            return response.json(false)
        } else {
            return response.json(true)
        }
    } else {
        return response.json(false)
    }
})

app.get('/posts', (request, response) => {
    const sql = 'SELECT * FROM posts'

    db.query(sql, (error, data) => {
        if(error) {
            return response.status(500).send(error)
        }

        if(data.length > 0) {
            response.send({ posts: data })
        } else {
            response.status(400).send({ error: 'Post not found' })
        }
    })
})

app.get('/posts/:id', (request, response) => {
    const postId = request.params.id;

    const sql = 'SELECT * FROM posts WHERE id = ?'

    db.query(sql, [postId], (error, data) => {
        if(error) {
            return response.status(500).send(error)
        }

        if(data.length > 0) {
            response.send({ post: data })
        } else {
            response.status(400).send({ error: 'Post not found' })
        }
    })
})


app.post('/posts/new', (request, response) => {
    const sql = 'INSERT INTO posts (`userId`, `postContent`, `createdAt`) VALUES (?)'

    const values = [
        request.body.id,
        request.body.postContent,
        request.body.createdAt
    ]

    db.query(sql, [values], (error, data) => {
        if (error) return response.json(error)
        return response.json(data)
    })
})

app.post('/posts/:id/like/new', (request, response) => {
    const postId = request.params.id;
    const userId = request.body.userId;

    const sql = 'INSERT INTO post_likes (`post_id`, `user_id`) VALUES (?)'
    const checkLikeSql = 'SELECT * FROM post_likes where post_id = ? AND user_id = ?';
    const deleteLikeSql = 'DELETE FROM post_likes WHERE post_id = ? AND user_id = ?';

    const values = [
        postId,
        userId
    ]

    db.query(checkLikeSql, [postId, userId], (error, data) => {
        if (error) return response.status(500).json({ error });

        if(data.length > 0) {
            db.query(deleteLikeSql, [postId, userId], (error, result) => {
                if (error) return response.status(500).json({ error });
                return response.json({ message: 'Like removed' });
            })
        } else {
            db.query(sql, [values], (error, data) => {
                if (error) return response.json(error)
                return response.json(data)
            })
        }
    })
})

app.get('/posts/:id/likes', (request, response) => {
    const postId = request.params.id;

    const sql = 'SELECT COUNT(*) FROM post_likes WHERE post_id = ?'

    db.query(sql, [postId], (error, data) => {
        if (error) return response.json(error)
        return response.json({ likeCount: data[0]["COUNT(*)"] })
    })
})

app.post('/posts/:id/liked', (request, response) => {
    const postId = request.params.id;
    const userId = request.body.userId;

    const sql = 'SELECT * FROM post_likes WHERE post_id = ? AND user_id = ?';

    db.query(sql, [postId, userId], (error, data) => {
        if (error) return response.json(error);
        return response.json({ isLiked: data.length > 0 });
    })
})

app.post('/posts/:id/delete', (request, response) => {
    const postId = request.params.id;
    const deleteLikesSql = 'DELETE FROM post_likes WHERE post_id = ?';
    
    db.query(deleteLikesSql, [postId], (error, results) => {
        if (error) return response.json(error);

        const deleteCommentsSql = 'DELETE FROM posts_comments WHERE postId = ?';

        db.query(deleteCommentsSql, [postId], (error, results) => {
            if (error) return response.json(error);
            
            const deletePostSql = 'DELETE FROM posts WHERE id = ?';
        
            db.query(deletePostSql, [postId], (error, results) => {
                if (error) return response.json(error);

                if (results.affectedRows === 0) {
                    return response.status(404).json({ error: 'Post not found' });
                }

                return response.status(200).json({ message: 'Post deleted successfully' });
            });
        })
    });
})

app.post('/posts/:id/update', (request, response) => {
    const postId = request.params.id;
    const { postContent, createdAt } = request.body;

    const sql = 'UPDATE posts SET postContent = ?, createdAt = ? WHERE id = ?';

    db.query(sql, [postContent, createdAt, postId], (error, results) => {
        if (error) return response.json(error);

        if (results.affectedRows === 0) {
            return response.status(404).json({ error: 'Post not found' });
        }

        return response.status(200).json({ message: 'Post updated successfully' });
    });
});

app.get('/comments/:id', (request, response) => {
    const postId = request.params.id;

    const sql = 'SELECT * FROM posts_comments WHERE postId = ?'

    db.query(sql, [postId], (error, data) => {
        if(error) {
            return response.status(500).send(error)
        }

        if(data.length > 0) {
            response.send({ comments: data })
        } else {
            response.status(400).send({ error: 'Post not found' })
        }
    })
})

app.post('/comments/:id/new', (request, response) => {
    const sql = 'INSERT INTO posts_comments (`userId`, `postId`, `commentContent`, `createdAt`) VALUES (?)'

    const values = [
        request.body.userId,
        request.params.id,
        request.body.commentContent,
        request.body.createdAt
    ]

    db.query(sql, [values], (error, data) => {
        if (error) return response.json(error)
        return response.json(data)
    })
})

app.post('/comment/:id/delete', (request, response) => {
    const commentId = request.params.id;
    const deleteCommentSql = 'DELETE FROM posts_comments WHERE id = ?';

    db.query(deleteCommentSql, [commentId], (error, results) => {
        if (error) return response.json(error);

        if (results.affectedRows === 0) {
            return response.status(404).json({ error: 'Comment not found' });
        }

        return response.status(200).json({ message: 'Comment deleted successfully' });
    });
});

app.get('/comment/:id', (request, response) => {
    const commentId = request.params.id;

    const sql = 'SELECT * FROM posts_comments WHERE id = ?'

    db.query(sql, [commentId], (error, data) => {
        if(error) {
            return response.status(500).send(error)
        }

        if(data.length > 0) {
            response.send({ comment: data })
        } else {
            response.status(400).send({ error: 'Post not found' })
        }
    })
})

app.post('/comment/:id/update', (request, response) => {
    const commentId = request.params.id;
    const { commentContent, createdAt } = request.body;

    const sql = 'UPDATE posts_comments SET commentContent = ?, createdAt = ? WHERE id = ?';

    db.query(sql, [commentContent, createdAt, commentId], (error, results) => {
        if (error) return response.json(error);

        if (results.affectedRows === 0) {
            return response.status(404).json({ error: 'Comment not found' });
        }

        return response.status(200).json({ message: 'Comment updated successfully' });
    });
});

app.listen(8000, () => {
    console.log('Server running...')
})