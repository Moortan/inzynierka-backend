const User = require('../models/userModel');
const Team = require('../models/teamModel')
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const config = require('../config')(process.env.NODE_ENV);
const { roles } = require('../config/roles');
const cookieParser = require('cookie-parser');
const moment = require('moment');
const randtoken = require('rand-token');
const ms = require('ms');
const dev = process.env.NODE_ENV !== 'production';


// refresh token list to manage the xsrf token
const refreshTokens = {};

// cookie options to create refresh token
const COOKIE_OPTIONS = {
    //domain: "localhost",
    httpOnly: true,
    secure: !dev,
    signed: true
};

async function hashPassword(password) {
    return await bcrypt.hash(password, 10);
}

async function validatePassword(plainPassword, hashedPassword) {
    return await bcrypt.compare(plainPassword, hashedPassword);
}

exports.verifyToken = async (token, xsrfToken, cb) => {
    const privateKey = process.env.JWT_SECRET + xsrfToken;
    jwt.verify(token, privateKey, cb);
}

exports.generateToken = async (user) => {
    try {
        if (!user) return null;

        const u = {
            userId: user._Id,
            email: user.email,
            username: user.username,
            //password: user.password,
            role: user.role
        };

        //generate xsrf token to generate access token
        const xsrfToken = randtoken.generate(24);

        //create private key by combine JWT secret and xsrf Token
        const privateKey = process.env.JWT_SECRET + xsrfToken;

        //generate access token and expiry date
        const token = jwt.sign(u, privateKey, { expiresIn: process.env.ACCESS_TOKEN_LIFE })

        //expiry time of the access token
        const expiredAt = moment().add(ms(process.env.ACCESS_TOKEN_LIFE), 'ms').valueOf();

        return {
            token,
            expiredAt,
            xsrfToken
        }
    } catch (error) {
        console.log(error.message);
    };

};

exports.generateRefreshToken = async (userId) => {
    if (!userId) return null;
    return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: process.env.REFRESH_TOKEN_LIFE });
};

exports.signup = async (req, res, next) => {
    try {
        let newUser;
        const { email, username, password, role } = req.body;

        User.findOne({ email: email }, async (err, user) => {
            if (user) return res.status(400).json({ auth: false, message: "email already exits" });

            User.findOne({ username: username }, async (err, user) => {
                if (user) return res.status(400).json({ auth: false, message: "username already exits" });

                const hashedPassword = await hashPassword(password);
                newUser = new User({ email, username, password: hashedPassword, role: role || "basic" });

                await newUser.save();
                res.json({
                    data: newUser,
                });
            });
        });
    } catch (error) {
        next(error);
    };
}

exports.login = async (req, res, next) => {
    try {

        const { email, password } = req.body;
        const user = await User.findOne({ $or: [{ email: email }, { username: email }] });

        if (!user || !await validatePassword(password, user.password)) {
            res.status(401).send('Wrong email or password');
            return (next())
        };

        const accessToken = await exports.generateToken(user);
        const refreshToken = await exports.generateRefreshToken(user._id);

        refreshTokens[refreshToken] = accessToken.xsrfToken;

        res.cookie('refreshToken', refreshToken, COOKIE_OPTIONS);
        res.cookie('XSRF-TOKEN', accessToken.xsrfToken);

        return await exports.handleResponse(req, res, 200, {
            user: user,
            token: accessToken.token,
            expiredAt: accessToken.expiredAt
        });
    } catch (error) {
        next(error);
    }
}

exports.clearTokens = async (req, res) => {
    const { signedCookies = {} } = req;
    const { refreshToken } = signedCookies;
    delete refreshTokens[refreshToken];
    res.clearCookie('XSRF-TOKEN');
    res.clearCookie('refreshToken', COOKIE_OPTIONS);
}

exports.logout = async (req, res, next) => {
    try {
        await exports.clearTokens(req, res)
        return await exports.handleResponse(req, res, 200);
    } catch (error) {
        next(error);
    }

};

exports.profile = async (req, res, next) => {
    try {
        return await exports.handleResponse(req, res, 200, {
            email: req.user.email,
            name: req.user.username
        });
    } catch (error) {
        next(error);
    }
}


exports.grantAccess = function (action, resource) {
    return async (req, res, next) => {
        try {
            const permission = roles.can(req.user.role)[action](resource);
            if (!permission.granted) {
                return await exports.handleResponse(req, res, 403)
            }
            next()
        } catch (error) {
            next(error)
        }
    }
}


exports.verifyTokens = async (req, res, next) => {

    const { signedCookies = {}} = req;
    const { refreshToken } = signedCookies;
    

    if (!refreshToken) {
        return await exports.handleResponse(req, res, 204);
    }

    //verify xsrf token
    const xsrfToken = req.headers['x-xsrf-token'];
    if (!xsrfToken || !(refreshToken in refreshTokens) || refreshTokens[refreshToken] !== xsrfToken) {
        return await exports.handleResponse(req, res, 401);
    }

    //verify refresh token
    exports.verifyToken(refreshToken, '', async (err, payload) => {
        if (err) {
            return await exports.handleResponse(req, res, 401)
        }
        else {
            const user = await User.findById(payload.userId);
            if (!user) {
                return await exports.handleResponse(req, res, 401);
            }

            //generate access token
            const accessToken = await exports.generateToken(user);

            refreshTokens[refreshToken] = accessToken.xsrfToken;
            res.cookie('XSRF-TOKEN', accessToken.xsrfToken);

            return await exports.handleResponse(req, res, 200, {
                user: user,
                token: accessToken.token,
                expiredAt: accessToken.expiredAt
            })
        }
    })

}

exports.allowIfLoggedin = async (req, res, next) => {
    try {
        if (req.headers['authorization']) {
            let accessToken = req.headers['authorization'];
            accessToken = accessToken.replace('Bearer ', '');
            
            const xsrfToken = req.headers['x-xsrf-token'];

            const { signedCookies = {} } = req;
            const { refreshToken } = signedCookies;

            console.log(refreshTokens);

            if (!refreshToken || !(refreshToken in refreshTokens) || refreshTokens[refreshToken] !== xsrfToken) {
                return await exports.handleResponse(req, res, 401);
            }

            exports.verifyToken(accessToken, xsrfToken, (err, payload) => {
                if (err) {
                    return exports.handleResponse(req, res, 401)
                } else {
                    req.user = payload;
                    next();
                }
            })
        }
        else {
            return await exports.handleResponse(req, res, 401);
        }
    } catch (error) {
        next(error);
    }
}

exports.handleResponse = async (req, res, statusCode, data, message) => {
    let isError = false;
    let errorMessage = message;
    switch (statusCode) {
        case 204:
            return res.sendStatus(204);
        case 400:
            isError = true;
            break;
        case 401:
            isError = true;
            errorMessage = message || 'Invalid user.';
            exports.clearTokens(req, res);
            break;
        case 403:
            isError = true;
            errorMessage = message || 'Access to this resource is denied.';
            exports.clearTokens(req, res);
            break;
        default:
            break;
    }
    const resObj = data || {};
    if (isError) {
        resObj.error = true;
        resObj.message = errorMessage;
    }
    return res.status(statusCode).json(resObj);
}
