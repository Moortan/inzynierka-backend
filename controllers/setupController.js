let Teams = require('../models/teamModel');
let Users = require('../models/userModel');


module.exports = app => {
    
    app.get('/api/setupTeams', (req, res) => {
        //seed database
        let starterTeams = [
            {
                teamLeader: 'Moortan',
                teamName: 'Team1',
                teamMembers: ['Moortan','Abi'],
                game: 'League of Legends'
            },
            {
                teamLeader: 'Moortan',
                teamName: 'Team2',
                teamMembers: ['Moortan', 'Krop', 'Abi'],
                game: 'League of Legends'
            }
        ];
        Teams.create(starterTeams, (err, results) => {
            res.send(results);
        })
    });

    app.get('/api/setupAdmin', (req, res) => {
        let starterAdmin = {
            username: "admin007",
            email: "admin@gmail.com",
            password: "admin",
            role: "admin"
        }
        Users.create(starterAdmin, (err, results) => {
            res.send(results);
        })

    })
}