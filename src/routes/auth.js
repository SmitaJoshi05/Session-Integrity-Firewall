// src/routes/auth.js
// Day 3 base + Day 4 update: bindSession added to login route.
// ONLY the login route changes — register and logout stay the same.

const express  = require('express')
const router   = express.Router()
const bcrypt   = require('bcryptjs')
const pool     = require('../db/connection')
const { issueToken }  = require('../utils/jwt')

// ← ADD THIS LINE (Day 4 change)
const { bindSession } = require('../modules/sessionBinder')

// ─────────────────────────────────────────────
// POST /auth/register
// ─────────────────────────────────────────────
router.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body

    const hashedPassword = await bcrypt.hash(password, 10)

    const result = await pool.query(
      `INSERT INTO users (username, email, password)
       VALUES ($1, $2, $3)
       RETURNING id, username, email`,
      [username, email, hashedPassword]
    )

    res.status(201).json({
      message: 'User created',
      user:    result.rows[0]
    })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// ─────────────────────────────────────────────
// POST /auth/login
// ─────────────────────────────────────────────
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body

    // 1. Find user
    const userRes = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    )
    if (userRes.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' })
    }

    const user = userRes.rows[0]

    // 2. Check password
    const valid = await bcrypt.compare(password, user.password)
    if (!valid) {
      return res.status(401).json({ error: 'Invalid credentials' })
    }

    // 3. Issue JWT
    const token = issueToken({ userId: user.id })

    // ← DAY 4 CHANGE: replaced manual hash+insert with bindSession
    // bindSession hashes IP, UA, device fingerprint and stores them in active_sessions.
    const sessionId = await bindSession(user.id, token, req)

    res.json({
      message:   'Login successful',
      token:     token,
      sessionId: sessionId    // optional: useful for debugging
    })

  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// ─────────────────────────────────────────────
// POST /auth/logout
// ─────────────────────────────────────────────
router.post('/logout', async (req, res) => {
  try {
    // req.sif is set by interceptor + sessionValidator (runs before this route)
    const tokenHash = req.sif?.tokenHash

    if (!tokenHash) {
      return res.status(400).json({ error: 'No token provided' })
    }

    await pool.query(
      `UPDATE active_sessions
       SET status = 'terminated'
       WHERE token_hash = $1 AND status = 'active'`,
      [tokenHash]
    )

    res.json({ message: 'Logged out successfully' })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

module.exports = router