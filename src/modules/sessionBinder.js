// src/modules/sessionBinder.js
// Person A — Day 4
// Called ONCE at login time (inside auth.js login route).
// Hashes the user's IP, UA, device fingerprint and token,
// then stores them in active_sessions.

const pool = require('../db/connection')
const { hashValue, buildDeviceHash, hashToken } = require('../utils/hash')

/**
 * bindSession — stores a hashed session fingerprint in active_sessions.
 *
 * @param {number} userId   - the authenticated user's ID
 * @param {string} token    - the raw JWT token just issued
 * @param {object} req      - the Express request object (for IP, UA headers)
 * @returns {string}        - the new session_id (UUID) from the DB
 */
async function bindSession(userId, token, req) {
  const ip         = req.ip || req.connection?.remoteAddress || 'unknown'
  const ua         = req.headers['user-agent']      || 'unknown'
  const acceptLang = req.headers['accept-language'] || ''

  const tokenHash  = hashToken(token)
  const ipHash     = hashValue(ip)
  const uaHash     = hashValue(ua)
  const deviceHash = buildDeviceHash(ip, ua, acceptLang)

  const result = await pool.query(
    `INSERT INTO active_sessions
       (user_id, token_hash, ip_hash, ua_hash, device_hash, status)
     VALUES ($1, $2, $3, $4, $5, 'active')
     RETURNING session_id`,
    [userId, tokenHash, ipHash, uaHash, deviceHash]
  )

  return result.rows[0].session_id
}

module.exports = { bindSession }