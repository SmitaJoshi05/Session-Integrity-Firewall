// src/app.js
// Updated for Day 6 — Person A wires interceptor + validator into the middleware chain.

require('dotenv').config({ path: './config/.env' })

const express = require('express')
const app     = express()

// --- Core middleware ---
app.use(express.json())

// CRITICAL: trust proxy so req.ip returns the real client IP, not the proxy IP.
// Without this, all IP hashes will be wrong and validation will always fail.
app.set('trust proxy', true)

// ─────────────────────────────────────────────
// SIF MIDDLEWARE — Person A's modules
// These run on EVERY request before any route handler.
// Order matters: interceptor must run before validator.
// ─────────────────────────────────────────────
const { interceptRequest } = require('./modules/interceptor')
const { validateSession }  = require('./modules/sessionValidator')

app.use(interceptRequest)  // Step 1: extract IP, UA, token → build req.sif
app.use(validateSession)   // Step 2: check req.sif hashes against DB → fill req.sif.valid

// ─────────────────────────────────────────────
// ROUTES
// ─────────────────────────────────────────────
const authRouter = require('./routes/auth')
app.use('/auth', authRouter)

// Health check — quick way to confirm server is up
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'SIF is running',
    time:   new Date().toISOString()
  })
})

// ─────────────────────────────────────────────
// ERROR HANDLERS (always at the bottom)
// ─────────────────────────────────────────────

// 404 — unknown route
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' })
})

// 500 — unhandled error in any route/middleware
app.use((err, req, res, next) => {
  console.error(err.stack)
  res.status(500).json({ error: 'Something went wrong' })
})

const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log(`SIF server running on port ${PORT}`)
})

module.exports = app