const jwt = require('jsonwebtoken')

const SECRET     = process.env.JWT_SECRET
const EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1h'

function issueToken(payload) {
  return jwt.sign(payload, SECRET, { expiresIn: EXPIRES_IN })
}

function verifyToken(token) {
  try {
    return { valid: true, decoded: jwt.verify(token, SECRET) }
  } catch (err) {
    return { valid: false, error: err.message }
  }
}

module.exports = { issueToken, verifyToken }