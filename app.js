const express = require('express')
const path = require('path')
const {open} = require('sqlite')
const sqlite3 = require('sqlite3')
const bcrypt = require('bcrypt')

const app = express()
app.use(express.json())

// Database path
const dbPath = path.join(__dirname, 'userData.db')
let db = null

// Initialize the database and server
const initializeDBAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    })
    app.listen(3000, () => {
      console.log('Server Running at http://localhost:3000/')
    })
  } catch (e) {
    console.log(`DB Error: ${e.message}`)
    process.exit(1)
  }
}
initializeDBAndServer()

/* API 1: Register */
app.post('/register', async (request, response) => {
  const {username, name, password, gender, location} = request.body

  // Check if the username already exists
  const selectQuery = `SELECT * FROM user WHERE username = ?`
  const user = await db.get(selectQuery, [username])

  if (user) {
    response.status(400).send('User already exists')
  } else if (password.length < 5) {
    response.status(400).send('Password is too short')
  } else {
    const hashedPassword = await bcrypt.hash(password, 10)
    const insertQuery = `
      INSERT INTO user (username, name, password, gender, location)
      VALUES (?, ?, ?, ?, ?)
    `
    await db.run(insertQuery, [
      username,
      name,
      hashedPassword,
      gender,
      location,
    ])
    response.status(200).send('User created successfully')
  }
})

/* API 2: Login */
app.post('/login', async (request, response) => {
  const {username, password} = request.body

  // Check if the user exists
  const selectQuery = `SELECT * FROM user WHERE username = ?`
  const dbUser = await db.get(selectQuery, [username])

  if (!dbUser) {
    response.status(400).send('Invalid user')
  } else {
    const isPasswordMatched = await bcrypt.compare(password, dbUser.password)

    if (isPasswordMatched) {
      response.status(200).send('Login success!')
    } else {
      response.status(400).send('Invalid password')
    }
  }
})

/* API 3: Change Password */
app.put('/change-password', async (request, response) => {
  const {username, oldPassword, newPassword} = request.body

  // Check if the user exists
  const selectQuery = `SELECT * FROM user WHERE username = ?`
  const dbUser = await db.get(selectQuery, [username])

  if (!dbUser) {
    response.status(400).send('Invalid user')
  } else {
    const isOldPasswordMatched = await bcrypt.compare(
      oldPassword,
      dbUser.password,
    )

    if (!isOldPasswordMatched) {
      response.status(400).send('Invalid current password')
    } else if (newPassword.length < 5) {
      response.status(400).send('Password is too short')
    } else {
      const hashedNewPassword = await bcrypt.hash(newPassword, 10)
      const updatePasswordQuery = `
        UPDATE user
        SET password = ?
        WHERE username = ?
      `
      await db.run(updatePasswordQuery, [hashedNewPassword, username])
      response.status(200).send('Password updated')
    }
  }
})

module.exports = app
