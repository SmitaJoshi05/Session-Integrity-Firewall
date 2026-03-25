// src/modules/sessionValidator.js
// Person A — Day 5
// Runs AFTER interceptor.js on every request.
// Checks the incoming request's fingerprint against what was stored at login.
// Fills in the rest of req.sif so Person B's risk engine can read it.

const pool         = require('../db/connection')
const { verifyToken } = require('../utils/jwt')

async function validateSession(req, res, next) {
  const sif = req.sif

  // --- 1. No token present — skip DB check, mark as unvalidated ---
  if (!sif.rawToken) {
    sif.valid  = false
    sif.reason = 'no_token'
    return next()
  }

  // --- 2. Verify the JWT signature and expiry ---
  const { valid: jwtValid, decoded } = verifyToken(sif.rawToken)
  if (!jwtValid) {
    sif.valid  = false
    sif.reason = 'invalid_token'
    return next()
  }

  sif.userId = decoded.userId

  try {
    // --- 3. Look up the active session by token hash ---
    const sessionRes = await pool.query(
      `SELECT *
       FROM active_sessions
       WHERE token_hash = $1
         AND status = 'active'
       LIMIT 1`,
      [sif.tokenHash]
    )

    // Session not found in DB (logged out, expired, or never existed)
    if (sessionRes.rows.length === 0) {
      sif.valid  = false
      sif.reason = 'session_not_found'
      return next()
    }

    const session    = sessionRes.rows[0]
    sif.sessionId   = session.session_id
    sif.sessionData = session

    // --- 4. Compare stored hashes vs current request hashes ---
    // This is the core SIF detection logic.
    sif.ipMatch     = session.ip_hash     === sif.ipHash
    sif.uaMatch     = session.ua_hash     === sif.uaHash
    sif.deviceMatch = session.device_hash === sif.deviceHash

    // --- 5. Concurrency check ---
    // Flag if the same token is being used from more than one IP simultaneously.
    // This catches session sharing / token theft.
    const concurrentRes = await pool.query(
      `SELECT COUNT(DISTINCT ip_hash) AS ip_count
       FROM active_sessions
       WHERE user_id    = $1
         AND token_hash = $2
         AND status     = 'active'`,
      [sif.userId, sif.tokenHash]
    )
    sif.concurrent = parseInt(concurrentRes.rows[0].ip_count, 10) > 1

    // --- 6. Final validity verdict ---
    // Order matters: check the most specific/severe condition first.
    if (sif.concurrent) {
      sif.valid  = false
      sif.reason = 'concurrent_session'
    } else if (!sif.ipMatch) {
      sif.valid  = false
      sif.reason = 'ip_mismatch'
    } else if (!sif.uaMatch) {
      sif.valid  = false
      sif.reason = 'ua_mismatch'
    } else if (!sif.deviceMatch) {
      sif.valid  = false
      sif.reason = 'device_mismatch'
    } else {
      sif.valid  = true
      sif.reason = 'ok'
    }

  } catch (err) {
    console.error('[sessionValidator] DB error:', err.message)
    sif.valid  = false
    sif.reason = 'db_error'
  }

  next()
}

module.exports = { validateSession }