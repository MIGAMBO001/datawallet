const jwt = require('jsonwebtoken');
const config = require('../config'); // Assuming there is a config file for secret.

const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) {
        return res.sendStatus(401); // Unauthorized
    }

    jwt.verify(token, config.secret, (err, user) => {
        if (err) {
            return res.sendStatus(403); // Forbidden
        }
        req.user = user;
        next();
    });
};

module.exports = authenticateToken;