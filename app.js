const express = require('express');
const app = express();
const mongoose = require('mongoose');
const db = require('./config')(process.env.NODE_ENV);
require('dotenv').config();
const setupController = require('./controllers/setupController');
const apiController = require('./controllers/apiController');
const rateLimiter = require('./middlewares/rateLimiter')
const userController = require('./controllers/userController');
const userRoutes = require('./routes/routeUser.js');
const teamRoutes = require('./routes/routeTeam.js')
const jwt = require('jsonwebtoken');
const User = require('./models/userModel')
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const cors = require('cors');

rateLimiter(app);

app.use(cors({ 
    origin: 'http://localhost:3007',
    credentials: true
}))

app.use(cookieParser(process.env.COOKIE_SECRET));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));


app.use('/assets', express.static(__dirname + '/public'));

//set view engine as ejs
app.set('view engine', 'ejs');

//database connection
mongoose.Promise = global.Promise;
mongoose.connect(db.DATABASE, { useNewUrlParser: true, useUnifiedTopology: true, useCreateIndex: true, useFindAndModify: false }, (err) => {
    if (err) throw err;
    console.log('database is connected')
});

setupController(app);

app.use('/', userRoutes);
app.use('/teams', teamRoutes);

//listening port
const PORT = process.env.PORT || 4200;
app.listen(PORT, () => {
    console.log(`app is live at port ${PORT}`)
});