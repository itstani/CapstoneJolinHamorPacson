require('dotenv').config(); // Load environment variables from .env file
const express = require('express');
const bodyParser = require('body-parser');
const { MongoClient } = require('mongodb');
const path = require('path');
const session = require('express-session');

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

// API route to handle user registration
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    // Validate input data
    if (!username || !email || !password) {
        return res.json({ message: 'Missing required fields', success: false });
    }

    try {
        await client.connect();
        const database = client.db(dbName);
        const usersCollection = database.collection('acc');

        // Check if the user already exists
        const existingUser = await usersCollection.findOne({ email });
        if (existingUser) {
            return res.json({ message: 'Email is already registered', success: false });
        }

        // Insert new user into the database
        const newUser = {
            username,
            email,
            password, // In a production system, you should hash the password before saving it
            createdAt: new Date(),
        };
        await usersCollection.insertOne(newUser);

        res.json({ message: 'Registration successful', success: true });
    } catch (error) {
        console.error("Error during registration:", error);
        res.json({ message: 'Registration failed', success: false });
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

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
