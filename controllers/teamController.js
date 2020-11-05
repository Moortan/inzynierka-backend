const Team = require('../models/teamModel')

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
        const teamId = req.params.teamId;
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
        const update = req.body
        const teamId = req.params.teamId;
        await Team.findByIdAndUpdate(teamId, update);
        const team = await Team.findById(teamId)
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
        const newTeam = new Team(req.body);

        await Team.findOne({ 'teamName': req.body.teamName }, async (err, team) => {
            if (team) return res.status(400).json({ message: `${req.body.teamName} is already taken team name` });

            await Team.findOne({ 'teamTag': req.body.teamTag }, (err, team) => {
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