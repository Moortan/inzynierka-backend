const rateLimit = require("express-rate-limit");

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, //15 minutes window
    max: 100
    })

const signupLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, //1 hour window
    max: 20, //block after 5 requests
    message: "Too many accounts created from this IP, please try again after an hour"
    })

const addTeamLimiter = rateLimit({
    windowMs: 24 * 60 * 60 * 1000, //24 hours window
    max: 20,
    message: "Too many teams created, please try again tomorrow"
})


module.exports = app => {
    app.use('/login', loginLimiter);
    app.use('/signup', signupLimiter);
    app.post('/teams', addTeamLimiter)
}
