const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const config = require('../config')(process.env.NODE_ENV);
const salt = 10;

const Schema = mongoose.Schema;

const userSchema = new Schema({
    username:{
        type: String,
        required: true,
        maxlength: 100
    },
    email:{
        type: String,
        required: true,
        trim: true,
        unique: 1
    },
    password:{
        type:String,
        required: true,
        minlength: 8
    },
    role: {
        type: String,
        default: 'basic',
        enum: ['basic', 'admin']
    },
    accessToken:{
        type: String
    }
});


module.exports = mongoose.model('User',userSchema);