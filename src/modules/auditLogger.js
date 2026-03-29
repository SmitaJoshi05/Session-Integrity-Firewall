// src/modules/auditLogger.js
const pool = require('../db/connection');

async function logEvent(req, res, next) {
    if (!req.sif) return next();

    const { 
        sessionId, userId, riskScore, riskLevel, decision, ipHash, uaHash 
    } = req.sif;

    try {
        await pool.query(
            `INSERT INTO session_events 
             (session_id, user_id, event_type, risk_score, risk_level, action_taken, ip_hash, ua_hash)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
            [
                sessionId || null,
                userId || null,
                'api_access',
                riskScore || 0,
                riskLevel || 'low',
                decision || 'allow',
                ipHash || null,
                uaHash || null
            ]
        );
    } catch (err) {
        // We log the error but DO NOT crash the app. 
        // We still want the enforcement layer to run.
        console.error('[auditLogger] DB error:', err.message);
    }

    next();
}

module.exports = { logEvent };