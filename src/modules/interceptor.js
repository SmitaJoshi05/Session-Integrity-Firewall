// src/modules/interceptor.js
// Person A — Day 4
// Runs on EVERY request before routes.
// Extracts IP, User-Agent, token from the request and attaches req.sif.
// sessionValidator.js will later fill in: ipMatch, uaMatch, concurrent, valid, reason.

const { hashValue, buildDeviceHash, hashToken } = require('../utils/hash')

function interceptRequest(req, res, next) {
  // --- 1. Extract raw values ---
  const ip         = req.ip || req.connection?.remoteAddress || 'unknown'
  const ua         = req.headers['user-agent']       || 'unknown'
  const acceptLang = req.headers['accept-language']  || ''

  // --- 2. Extract token from Authorization: Bearer <token> ---
  const authHeader = req.headers['authorization'] || ''
  const rawToken   = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null

  // --- 3. Build req.sif skeleton ---
  // This object is the shared interface between Person A (you) and Person B (risk engine).
  // Fields marked "set by sessionValidator" will be filled in the next middleware.
  req.sif = {
    // Raw values (never stored in DB — only used for hashing)
    rawIp:    ip,
    rawUa:    ua,
    rawToken: rawToken,

    // Hashed fingerprints (used for DB comparison)
    ipHash:     hashValue(ip),
    uaHash:     hashValue(ua),
    deviceHash: buildDeviceHash(ip, ua, acceptLang),
    tokenHash:  rawToken ? hashToken(rawToken) : null,

    // Set by sessionValidator.js ↓
    userId:      null,   // decoded from JWT
    sessionId:   null,   // UUID from active_sessions
    sessionData: null,   // full row from active_sessions
    ipMatch:     null,   // true if current IP hash === stored IP hash
    uaMatch:     null,   // true if current UA hash === stored UA hash
    deviceMatch: null,   // true if device hash matches
    concurrent:  false,  // true if same token used from 2+ IPs simultaneously
    valid:       false,  // final validity verdict
    reason:      'not_checked' // explanation string for Person B's risk engine
  }

  next()
}

module.exports = { interceptRequest }