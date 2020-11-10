const mongoose = require('mongoose');

const Schema = mongoose.Schema;

const teamSchema = new Schema({
    teamLeader: {
        type: String,
        required: true,
        maxlength: 32
    },
    teamName: {
        type: String,
        required: true,
        maxlength: 32
    },
    teamMembers: [{
        type: String
    }],
    teamTag: {
        type: String,
        required: true,
        maxlength: 5
    },
    game: {
        type: String,
        required: true,
        enum: ['League of Legends', 'Counter Strike: Global Offensive', 'Dota 2']
    },
});

module.exports = mongoose.model('Team', teamSchema);