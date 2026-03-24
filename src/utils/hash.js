const crypto = require('crypto')

function hashValue(value) {
  return crypto
    .createHash('sha256')
    .update(String(value))
    .digest('hex')
}

function buildDeviceHash(ip, userAgent, acceptLanguage = '') {
  const raw = `${ip}::${userAgent}::${acceptLanguage}`
  return hashValue(raw)
}

function hashToken(token) {
  return hashValue(token)
}

module.exports = { hashValue, buildDeviceHash, hashToken }