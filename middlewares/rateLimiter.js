const rateLimit = require("express-rate-limit");

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, //15 minutes window
    max: 20
    })

const signupLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, //1 hour window
    max: 5, //block after 5 requests
    message: "Too many accounts created from this IP, please try again after an hour"
    })


module.exports = app => {
    app.use('/login', loginLimiter);
    app.use('/signup', signupLimiter);
}
