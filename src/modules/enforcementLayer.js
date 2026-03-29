// src/modules/enforcementLayer.js
function enforce(req, res, next) {
    if (!req.sif) {
        return res.status(500).json({ error: 'SIF Pipeline missing or broken' });
    }

    const { decision, reason, riskLevel } = req.sif;

    if (decision === 'block') {
        return res.status(403).json({
            error: 'Access Denied: High risk detected.',
            reason: reason,
            risk_level: riskLevel
        });
    }

    if (decision === 'challenge') {
        return res.status(401).json({
            error: 'Verification Required: Device or context changed.',
            reason: reason
        });
    }

    // If decision is 'allow', we let the user through to the route they requested!
    next();
}

module.exports = { enforce };