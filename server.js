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
            // Check if the user is an admin
            const isAdmin = user.email === "admin@example.com" && password === password;

            // Set session data
            req.session.user = { username: user.username, email: user.email };

            // Include the isAdmin flag in the response
            res.json({ message: 'Login successful', success: true, username: user.username, email: user.email, isAdmin });
        } else {
            res.json({ message: 'Invalid email or password', success: false });
        }
    } catch (error) {
        res.json({ message: 'An error occurred', success: false });
    }
});


// API route to handle user registration
app.post('/register', async (req, res) => {
    const { username,lastname, email, password } = req.body;

    // Validate input data
    if (!username || !lastname || !email || !password) {
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
            lastname,
            email,
            password, // In a production system, you should hash the password before saving it
            status: "to be verified", //homeowner monthly status to be verified by admin if paid or not
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
app.post('/addevent', async (req, res) => {
    const { hostName, eventName, eventDate, eventTime, amenity, guests, homeownerStatus } = req.body;

    // Validate input data
    if (!hostName || !eventName || !eventDate || !eventTime || !amenity || !guests || !homeownerStatus) {
        return res.json({ message: 'Missing required fields', success: false });
    }

    try {
        // Connect to the MongoDB client
        await client.connect();
        const database = client.db(dbName);
        const eventsCollection = database.collection('events'); // Connect to Reservations collection

        // Check for duplicates
    const existingEvent = await eventsCollection.findOne({
        eventName: eventName,
        eventDate: eventDate,
        amenity: amenity,
        homeownerStatus: homeownerStatus,
        hostName: hostName, 
      });
  
      if (existingEvent) {
        return res.json({
          success: false,
          message: "Duplicate reservation detected.",
        });
      }

        // Prepare the new event data
        const newEvent = {
            hostName, 
            eventName,
            eventDate,
            eventTime, 
            amenity,
            guests: parseInt(guests, 10), // Ensure guests is a number
            homeownerStatus,
            createdBy: req.session.user || null, // user data eent creator
            createdAt: new Date(),
        };

        // Insert the new event into the Reservations collection
            await eventsCollection.insertOne(newEvent);

       // Return success response if event is created successfully
       
            res.json({ message: 'Event created successfully', success: true });
           
        
          
        

    } catch (error) {
        console.error("Error during event creation:", error);
        res.json({ message: 'Error creating event', success: false });
    }
});

// using back button in eventfin delete recent event added to reenter new one
app.post('/delEvent', async (req, res) => {
    const { username } = req.body;

    try {
        await client.connect();
        const database = client.db(dbName);
        const eventsCollection = database.collection('events');

        // Find and delete the most recent event by this user
        const result = await eventsCollection.findOneAndDelete(
            { "createdBy.username": username },
            { sort: { createdAt: -1 } } // Sort by most recent first
        );

        if (result.value) {
            res.json({ success: true, message: 'Most recent event deleted successfully.' });
        } else {
            res.json({ success: false, message: 'cancelled' });
        }
    } catch (error) {
        console.error("Error deleting recent event:", error);
        res.status(500).json({ success: false, message: 'Error deleting recent event.' });
    } finally {
        await client.close();
    }
});


app.get('/eventfin', async (req, res) => {
    try {
        await client.connect();
        const database = client.db(dbName);
        const eventsCollection = database.collection('events');


        const events = await eventsCollection.find({}).toArray();

      
        res.render('eventfin', { events });
    } catch (error) {
        console.error("Error fetching events:", error);
        res.status(500).send('An error occurred while fetching events');
    }

});


app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
