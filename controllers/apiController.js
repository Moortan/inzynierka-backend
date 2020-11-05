const Teams = require('../models/teamModel');
const bodyParser = require('body-parser');
const User = require('../models/userModel');
const {auth} =require('../middlewares/auth.js');
const cookieParser = require('cookie-parser');
const userController = require('./userController')

module.exports = app => {

    app.use(cookieParser());
    app.use(bodyParser.json());
    app.use(bodyParser.urlencoded({extended: true }));

    // get logged in user
    app.get('/api/profile', auth, function(req, res){
        res.json({
            isAuth: true,
            id: req.user._id,
            email: req.user.email,
            name: req.user.username
            
        })
    });


    //display team members
    app.get('/api/teams/:teamname', auth, (req, res) => {

        Teams.find({ teamName: req.params.teamname}, (err, teams) => {
            if (err) throw err;

            res.send(teams);
        });
    });

    app.get('/api/teams/all', auth, (req, res) => {
        //returns empty TO FIX!
        res.send(Teams.find());

    });

    app.post('/api/teams/addTeam', auth, (req, res) => {
        const newTeam = new Teams(req.body);

        Teams.findOne({'teamName':req.body.teamName}, (err, team) => {
            if(team) return res.status(400).json({message: `${req.body.teamName} is already taken team name`});

            Teams.findOne({'teamTag':req.body.teamTag}, (err, team) => {
                if(team) return res.status(400).json({message: `${req.body.teamTag} is already taken team tag`});

                newTeam.save((err,doc)=>{
                    if(err) {console.log(err);
                    return res.status(400).json({ success : false});}
                    res.status(200).json({
                        succes: true,
                        team : doc
                    });
                });
            });
        })
    });
};