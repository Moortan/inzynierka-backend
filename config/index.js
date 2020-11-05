require('dotenv').config();

const config = {
    production :{
        SECRET: process.env.SECRET,
        DATABASE: process.env.MONGODB_URI
    },
    default : {
        SECRET: 'mysecretkey',
        DATABASE: `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.z1d3d.mongodb.net/devdatabase?retryWrites=true&w=majority`
    }
}

module.exports = (env) => {
        return  config[env] || config.default;
}