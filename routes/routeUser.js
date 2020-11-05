const express = require('express');
const router = express.Router();
const rateLimiter = require('../middlewares/rateLimiter')
const userController = require('../controllers/userController');
const teamController = require('../controllers/teamController');


router.post('/signup', userController.signup);

router.post('/login', userController.login);

router.get('/profile', userController.allowIfLoggedin, userController.profile);

router.get('/myteams', userController.allowIfLoggedin, teamController.getMyTeams);

//TO DO
router.post('/logout'/*,userController.allowIfLoggedin*/, userController.logout);


//TO DO
router.post('/verifyTokens'/*, userController.allowIfLoggedin*/, userController.verifyTokens);

module.exports = router;