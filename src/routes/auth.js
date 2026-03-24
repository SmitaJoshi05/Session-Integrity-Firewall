const express   = require('express')
const bcrypt    = require('bcryptjs')
const router    = express.Router()
const pool      = require('../db/connection')
const { issueToken }              = require('../utils/jwt')
const { hashValue, buildDeviceHash, hashToken } = require('../utils/hash')

// ─── Helper: extract client IP ───────────────────────────────────────────────
function getClientIP(req) {
  return (
    req.headers['x-forwarded-for']?.split(',')[0].trim() ||
    req.socket.remoteAddress ||
    'unknown'
  )
}

// ─── POST /auth/register ─────────────────────────────────────────────────────
router.post('/register', async (req, res) => {
  const { username, email, password } = req.body

  if (!username || !email || !password)
    return res.status(400).json({ error: 'username, email and password are required' })

  try {
    const hashed = await bcrypt.hash(password, 12)

    const result = await pool.query(
      `INSERT INTO users (username, email, password)
       VALUES ($1, $2, $3)
       RETURNING id, username, email, created_at`,
      [username, email, hashed]
    )

    res.status(201).json({
      message: 'User registered successfully',
      user: result.rows[0]
    })
  } catch (err) {
    if (err.code === '23505')
      return res.status(409).json({ error: 'Username or email already exists' })
    console.error('Register error:', err.message)
    res.status(500).json({ error: 'Internal server error' })
  }
})

// ─── POST /auth/login ─────────────────────────────────────────────────────────
router.post('/login', async (req, res) => {
  const { email, password } = req.body

  if (!email || !password)
    return res.status(400).json({ error: 'email and password are required' })

  try {
    // 1. Find user
    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    )
    const user = result.rows[0]
    if (!user)
      return res.status(401).json({ error: 'Invalid credentials' })

    // 2. Verify password
    const valid = await bcrypt.compare(password, user.password)
    if (!valid)
      return res.status(401).json({ error: 'Invalid credentials' })

    // 3. Issue JWT
    const token = issueToken({ userId: user.id, username: user.username })

    // 4. Extract context from request
    const ip             = getClientIP(req)
    const userAgent      = req.headers['user-agent'] || 'unknown'
    const acceptLanguage = req.headers['accept-language'] || ''

    // 5. Build hashes — we never store raw IP or UA
    const ipHash     = hashValue(ip)
    const uaHash     = hashValue(userAgent)
    const devHash    = buildDeviceHash(ip, userAgent, acceptLanguage)
    const tokenHash  = hashToken(token)

    // 6. Store session binding in active_sessions
    await pool.query(
      `INSERT INTO active_sessions
         (user_id, token_hash, ip_hash, ua_hash, device_hash, status)
       VALUES ($1, $2, $3, $4, $5, 'active')`,
      [user.id, tokenHash, ipHash, uaHash, devHash]
    )

    // 7. Log the login event in session_events
    await pool.query(
      `INSERT INTO session_events
         (user_id, event_type, risk_score, risk_level, action_taken, ip_hash, ua_hash)
       VALUES ($1, 'login', 0, 'low', 'session_created', $2, $3)`,
      [user.id, ipHash, uaHash]
    )

    res.status(200).json({
      message: 'Login successful',
      token,
      user: { id: user.id, username: user.username, email: user.email }
    })

  } catch (err) {
    console.error('Login error:', err.message)
    res.status(500).json({ error: 'Internal server error' })
  }
})

// ─── POST /auth/logout ────────────────────────────────────────────────────────
router.post('/logout', async (req, res) => {
  const authHeader = req.headers['authorization']
  if (!authHeader?.startsWith('Bearer '))
    return res.status(401).json({ error: 'No token provided' })

  const token     = authHeader.split(' ')[1]
  const tokenHash = hashToken(token)

  try {
    const result = await pool.query(
      `UPDATE active_sessions
       SET status = 'terminated', last_seen = NOW()
       WHERE token_hash = $1 AND status = 'active'
       RETURNING session_id, user_id`,
      [tokenHash]
    )

    if (result.rowCount === 0)
      return res.status(404).json({ error: 'Session not found or already terminated' })

    const { session_id, user_id } = result.rows[0]

    await pool.query(
      `INSERT INTO session_events
         (session_id, user_id, event_type, risk_score, risk_level, action_taken)
       VALUES ($1, $2, 'logout', 0, 'low', 'session_terminated')`,
      [session_id, user_id]
    )

    res.status(200).json({ message: 'Logged out successfully' })

  } catch (err) {
    console.error('Logout error:', err.message)
    res.status(500).json({ error: 'Internal server error' })
  }
})

module.exports = router