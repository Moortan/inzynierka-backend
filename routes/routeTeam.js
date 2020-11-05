const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const teamController = require('../controllers/teamController');

router.get('/:teamId', userController.allowIfLoggedin, teamController.getTeam);

router.post('/', userController.allowIfLoggedin, teamController.addTeam);

router.get('/', userController.allowIfLoggedin, userController.grantAccess('readAny', 'profile'), teamController.getTeams);

router.put('/:teamId', userController.allowIfLoggedin, userController.grantAccess('updateAny', 'profile'), teamController.updateTeam);

router.delete('/:teamId', userController.allowIfLoggedin, userController.grantAccess('deleteAny', 'profile'), teamController.deleteTeam);

module.exports = router;