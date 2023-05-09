function sessionAuthentication(req, res, next){
    if (req.session.authenticated){
        next();
    } else {
        res.redirect('/login');
    }
}

function adminAuthorization(req, res, next){
    if (req.session.usertype == "admin"){
        next();
    } else {
        res.status(403);
        res.render('403', {navbar: navbar});
    }
}

const express = require('express');
const session = require('express-session');
const mongo = require('connect-mongo');
const bcrypt = require('bcrypt');
require('dotenv').config();
const joi = require('joi');
const url = require('url');

var navbar = [];

const node_session_secret = process.env.SESSION_SECRET;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_PW = process.env.MONGODB_PW;
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const mongodb_database = process.env.MONGODB_DATABASE;
const sessionExpiryTime = 60 * 60 * 1000; // milliseconds
const salt = 10;

const app = express();
const port = process.env.PORT || 8000;
app.listen(port, () => {
    console.log("Now listening on port " + port + ".");
});

var atlasURL = `mongodb+srv://${mongodb_user}:${mongodb_PW}@${mongodb_host}/`
var MongoDBStore = mongo.create({
    mongoUrl: atlasURL + 'sessions',
    crypto: {secret: mongodb_session_secret}
});
const MongoClient = require('mongodb').MongoClient;
const database = new MongoClient(atlasURL + '?retryWrites=true', {useNewUrlParser: true, useUnifiedTopology: true});
const users = database.db(mongodb_database).collection('users_with_types');

app.use(session({
    secret: node_session_secret,
    store: MongoDBStore,
    saveUninitialized: false,
    resave: true
}));

function populateNavbar(req, res, next) {
    navbar = [{name: 'Home', link: '/'}];
    if (req.session.authenticated){
        navbar.push({name: 'Members', link: '/members'}, 
                    {name: 'Log Out', link:'/logout'});
                    console.log(req.session.usertype);
        if (req.session.usertype == 'admin'){
            navbar.push({name: 'Admin', link: '/admin'});
        }
    } else {
        navbar.push({name: 'Log In', link: '/login'}, 
                    {name: 'Sign Up', link:'/signup'});
    }
    next();
}

app.use("/", populateNavbar);

app.use(express.urlencoded({extended:false}));
app.use(express.static(__dirname + '/public'));

app.set('view engine', 'ejs');

app.get('/', (req, res) => {
    res.render('index', {navbar: navbar});
});

app.get('/login', (req, res) => {
    res.render('login', {navbar: navbar});
})

app.get('/signup', (req, res) => {
    res.render('signup', {navbar: navbar});
})

app.get('/members', sessionAuthentication, (req, res) => {
    res.render('members', {firstname: req.session.firstname, navbar: navbar});
})

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
})

app.get('/admin', sessionAuthentication, adminAuthorization, async (req, res) => {
    var userList = await users.find().project({email: 1, firstname: 1, type: 1, _id: 1}).toArray();
    res.render('admin', {users: userList, navbar: navbar});
    // TODO allow promotion and demotion
})

app.get('*', (req, res) => {
    res.status(404);
    res.render('404', {navbar: navbar});
});

app.post('/log_user_in', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;
    var schema = joi.object({
        email: joi.string().max(20).required(),
        password: joi.string().max(20).required(),
    });
    var validCredentials = schema.validate({email, password});

    if (validCredentials.error != null){
        res.render('tryagain', {error: validCredentials.error.toString().substring(17), link: '/login', navbar: navbar});
    } else {
        var user = await users.find({email: email})
            .project({email: 1, password: 1, firstname: 1, type: 1, _id: 1})
            .toArray();
        if (user.length != 1){
            res.render('tryagain', {error: 'Account does not exist for this email.', link: '/login', navbar: navbar});
        } else if (await bcrypt.compare(password, user[0].password)){
            req.session.authenticated = true;
            req.session.firstname = user[0].firstname;
            req.session.email = email;
            req.session.cookie.maxAge = sessionExpiryTime;
            req.session.usertype = user[0].type;
            res.redirect('/members');
        } else {
            res.render('tryagain', {error: 'Incorrect password', link: '/login', navbar: navbar});
        }
    }
})

app.post('/register_user', async (req, res) => {
    var firstname = req.body.firstname;
    var email = req.body.email;
    var password = req.body.password;

    var schema = joi.object({
        firstname: joi.string().alphanum().max(20).required(),
        email: joi.string().max(20).required(),
        password: joi.string().max(20).required(),
    });
    var validSubmission = schema.validate({firstname, email, password});

    if (validSubmission.error != null){
        res.render('tryagain', {error: validCredentials.error.toString().substring(17), link: '/signup', navbar: navbar});
    } else {
        var encrypted_password = await bcrypt.hash(password, salt); 
        await users.insertOne({
            email: email,
            password: encrypted_password,
            firstname: firstname,
            type: 'user'
        })
        req.session.authenticated = true;
        req.session.firstname = firstname;
        req.session.email = email;
        req.session.cookie.maxAge = sessionExpiryTime;
        req.session.usertype = 'user';
        res.redirect('/members');
    }
})

app.post('/changetype', adminAuthorization, async (req, res) => {
    var input = req.body.target;
    var typeID = input.charAt(0);
    var newType = typeID == 'U' ? 'user' : 'admin';
    var subjectEmail = input.substring(1);
    await users.findOneAndUpdate({email: subjectEmail}, {$set: {type: newType}});
    res.redirect('/admin');
})


    