// src/modules/decisionEngine.js
function makeDecision(req, res, next) {
    if (!req.sif) return next();

    const { riskLevel } = req.sif;
    let decision = 'allow';

    if (riskLevel === 'critical') {
        decision = 'block';
    } else if (riskLevel === 'high') {
        decision = 'challenge'; // e.g., trigger MFA or re-login
    }

    req.sif.decision = decision;
    next();
}

module.exports = { makeDecision };