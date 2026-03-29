// src/modules/riskEngine.js
function evaluateRisk(req, res, next) {
    if (!req.sif) return next();

    let score = 0;
    let level = 'low';

    // Person A's validator flags the session as invalid and gives a reason
    if (!req.sif.valid) {
        switch(req.sif.reason) {
            case 'concurrent_session':
                score = 95;
                level = 'critical';
                break;
            case 'ip_mismatch':
                score = 85;
                level = 'critical';
                break;
            case 'device_mismatch':
            case 'ua_mismatch':
                score = 65;
                level = 'high';
                break;
            case 'session_not_found':
            case 'invalid_token':
            case 'no_token':
                score = 100;
                level = 'critical';
                break;
            default:
                score = 50;
                level = 'medium';
        }
    } else {
        // Session is totally valid
        score = 0;
        level = 'low';
    }

    // Attach to the SIF object for the next module
    req.sif.riskScore = score;
    req.sif.riskLevel = level;

    next();
}

module.exports = { evaluateRisk };