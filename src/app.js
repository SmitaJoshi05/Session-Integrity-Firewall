// src/app.js
// Final Version - Wires together Person A, Person B, and Person C

require('dotenv').config({ path: './config/.env' })

const express = require('express')
const app     = express()

// --- Core middleware ---
app.use(express.json())

// CRITICAL: trust proxy so req.ip returns the real client IP, not the proxy IP.
// Without this, all IP hashes will be wrong and validation will always fail.
app.set('trust proxy', true)

// ─────────────────────────────────────────────
// IMPORTS - ALL MODULES (A, B, C)
// ─────────────────────────────────────────────
// Person A
const { interceptRequest } = require('./modules/interceptor')
const { validateSession }  = require('./modules/sessionValidator')
// Person B
const { evaluateRisk }     = require('./modules/riskEngine')
const { makeDecision }     = require('./modules/decisionEngine')
// Person C
const { logEvent }         = require('./modules/auditLogger')
const { enforce }          = require('./modules/enforcementLayer')

// ─────────────────────────────────────────────
// SIF PIPELINE
// ─────────────────────────────────────────────
// This array dictates the exact order of operations for the firewall.
const sifPipeline = [
    interceptRequest, // A: extract IP, UA, token → build req.sif
    validateSession,  // A: check req.sif hashes against DB → fill req.sif.valid
    evaluateRisk,     // B: calculate risk score based on validation
    makeDecision,     // B: decide whether to allow, block, or challenge
    logEvent,         // C: log the event to session_events DB
    enforce           // C: actually block the request or let it pass
]

// ─────────────────────────────────────────────
// ROUTES
// ─────────────────────────────────────────────
// 1. PUBLIC ROUTES (No SIF Pipeline here)
const authRouter = require('./routes/auth')
app.use('/auth', authRouter)

// 2. PROTECTED ROUTES (SIF Pipeline applied here!)
// Notice how we pass `sifPipeline` as middleware before the route logic
app.get('/health', sifPipeline, (req, res) => {
  res.status(200).json({
    status: 'SIF is running securely',
    time:   new Date().toISOString(),
    sifData: req.sif // This will return the whole SIF object so you can see it working!
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