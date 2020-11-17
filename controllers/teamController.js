const Team = require('../models/teamModel')
const validate = require('../middlewares/validator')
var sanitize = require('mongo-sanitize');

exports.getTeams = async (req, res, next) => {
    try {
        const teams = await Team.find({});
        res.status(200).json({
            data: teams
        });
    } catch (error) {
        next(error);
    }
}

exports.getTeam = async (req, res, next) => {
    try {
        const teamId = sanitize(req.params.teamId);
        const team = await Team.findById(teamId);
        if (!team) return next(new Error('Team does not exist'));
        res.status(200).json({
            data: team
        });
    } catch (error) {
        next(error);
    }
}

exports.getMyTeams = async (req, res, next) => {
    try {
        const teams = await Team.find({"teamLeader": req.user.username })

        if(!teams) return next (new Error('You have no teams'));
        res.status(200).json({
            teams
        })

    } catch (error) {
        next(error);
    }
}

exports.updateTeam = async (req, res, next) => {
    try {
        const update = sanitize(req.body);
        const teamId = req.params.teamId;
        await Team.findByIdAndUpdate(teamId.toString(10), update.toString(10));
        const team = await Team.findById(teamId.toString(10))
        res.status(200).json({
            data: team,
            message: 'Team has been updated'
        });
    } catch (error) {
        next(error)
    }
}

exports.deleteTeam = async (req, res, next) => {
    try {
        const teamId = req.params.teamId;
        await Team.findByIdAndDelete(teamId);
        res.status(200).json({
            data: null,
            message: 'Team has been deleted'
        });
    } catch (error) {
        next(error)
    }
}

exports.addTeam = async (req, res, next) => {
    try {
        const newTeam = new Team(sanitize(req.body));

        newTeam.teamMembers = newTeam.teamMembers.map( x => x.toString(10));
        newTeam.teamName = newTeam.teamName.toString(10);
        newTeam.teamTag = newTeam.teamTag.toString(10)
        newTeam.game = newTeam.game.toString(10)

        if(!newTeam.teamMembers.every(x => validate.isAlphaNumericOnly(x))) {
            return res.status(400).json({message: "Each Team Member name can be alphanumeric only"})
        }
        if(!validate.isAlphaNumericOnly(newTeam.teamName) || !validate.isLongEnough(newTeam.teamName)){
            return res.status(400).json({message: "Team Name must contain at least 6 characters and can be alphanumeric only"})
        }
        if(!validate.isTeamTagValid(newTeam.teamTag)){
            return res.status(400).json({message: "Team Tag must be 2-5 characters and can be alphanumeric only"})
        }

        await Team.findOne({ 'teamName': req.body.teamName.toString(10) }, async (err, team) => {
            if (team) return res.status(400).json({ message: `${req.body.teamName} is already taken team name` });

            await Team.findOne({ 'teamTag': req.body.teamTag.toString(10) }, (err, team) => {
                if (team) return res.status(400).json({ message: `${req.body.teamTag} is already taken team tag` });

                newTeam.save((err, doc) => {
                    if (err) {
                        console.log(err);
                        return res.status(400).json({ success: false });
                    }
                    res.status(200).json({
                        succes: true,
                        team: doc
                    });
                });
            });
        })
    } catch (error) {
        next(error);
    }
};