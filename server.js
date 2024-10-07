require('dotenv').config(); // Load environment variables from .env file
const express = require('express');
const bodyParser = require('body-parser');
const { MongoClient } = require('mongodb');
const path = require('path');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;

const app = express();
const port = 3000;

const uri = 'mongodb://localhost:27017/';
const client = new MongoClient(uri);
const dbName = 'avidadb';

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'Webpages')));
app.use('/images', express.static(path.join(__dirname, 'images')));

// Session setup
app.use(session({
    secret: 'your-secret-key', // Change this to a secure key
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Set to true if using https
}));

app.use(passport.initialize());
app.use(passport.session());

// Serialize and deserialize user
passport.serializeUser((user, done) => {
    done(null, user);
});

passport.deserializeUser((user, done) => {
    done(null, user);
});

// Configure Google Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: '/auth/google/callback'
}, async (token, tokenSecret, profile, done) => {
    try {
        await client.connect();
        const database = client.db(dbName);
        const usersCollection = database.collection('acc');

        let user = await usersCollection.findOne({ googleId: profile.id });

        if (!user) {
            user = await usersCollection.insertOne({
                username: profile.displayName,
                email: profile.emails[0].value,
                googleId: profile.id,
            });
        }

        done(null, user);
    } catch (err) {
        done(err, null);
    }
}));

// Configure Facebook Strategy
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: '/auth/facebook/callback',
    profileFields: ['id', 'displayName', 'emails']
}, async (accessToken, refreshToken, profile, done) => {
    try {
        await client.connect();
        const database = client.db(dbName);
        const usersCollection = database.collection('acc');

        let user = await usersCollection.findOne({ facebookId: profile.id });

        if (!user) {
            user = await usersCollection.insertOne({
                username: profile.displayName,
                email: profile.emails ? profile.emails[0].value : '',
                facebookId: profile.id,
            });
        }

        done(null, user);
    } catch (err) {
        done(err, null);
    }
}));

// Routes for Google and Facebook authentication
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/' }), (req, res) => {
    res.redirect('/dashboard');
});

app.get('/auth/facebook', passport.authenticate('facebook', { scope: ['email'] }));

app.get('/auth/facebook/callback', passport.authenticate('facebook', { failureRedirect: '/' }), (req, res) => {
    res.redirect('/dashboard');
});

// Protected dashboard route
app.get('/dashboard', (req, res) => {
    if (req.isAuthenticated()) {
        res.json({ message: 'Welcome to your dashboard', user: req.user });
    } else {
        res.redirect('/');
    }
});

// Serve the login page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'Webpages/login.html'));
});

// API route to handle manual login
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        await client.connect();
        const database = client.db(dbName);
        const usersCollection = database.collection('acc');
        const user = await usersCollection.findOne({ email });
        if (user && user.password === password) {
            req.session.user = { username: user.username, email: user.email };
            res.json({ message: 'Login successful', success: true });
        } else {
            res.json({ message: 'Invalid email or password', success: false });
        }
    } catch (error) {
        res.json({ message: 'An error occurred', success: false });
    }
});

// API route to add a new event
app.post('/add-event', async (req, res) => {
    console.log("Request body:", req.body);
    const { eventName, eventDate, amenity, guests, homeownerStatus } = req.body;

    // Check if the user is logged in
    if (!req.session.user) {
        return res.json({ message: 'User not logged in', success: false });
    }

    const { username, email } = req.session.user;

    // Validate the input data
    if (!eventName || !eventDate || !amenity || !guests || !homeownerStatus) {
        return res.json({ message: 'Missing required fields', success: false });
    }

    const newEvent = {
        eventName,
        eventDate,
        amenity,
        guests: parseInt(guests, 10),
        homeownerStatus,
        createdBy: { username, email },
        createdAt: new Date()
    };

    try {
        const database = client.db(dbName);
        const eventsCollection = database.collection('events');
        const result = await eventsCollection.insertOne(newEvent);
        console.log("Inserted event:", result);
        res.json({ message: 'Event created successfully', success: true });
    } catch (error) {
        console.error("Error inserting event:", error);
        res.json({ message: 'Failed to create event', success: false });
    }
});

// Start the server
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
