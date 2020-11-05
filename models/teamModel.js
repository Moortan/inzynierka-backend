const mongoose = require('mongoose');

const Schema = mongoose.Schema;

const teamSchema = new Schema({
    teamLeader: {
        type: String,
        required: true,
        maxlength: 100
    },
    teamName: {
        type: String,
        required: true,
        maxlength: 100
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
        maxlength: 100
    },
});

module.exports = mongoose.model('Team', teamSchema);