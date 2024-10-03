const express = require('express');
const bodyParser = require('body-parser');
const { MongoClient } = require('mongodb');
const path = require('path');
const session = require('express-session'); // Add session handling

const app = express();
const port = 3000;

// Middleware to parse incoming request bodies
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static files from 'Webpages' and 'images'
app.use(express.static(path.join(__dirname, 'Webpages')));
app.use('/images', express.static(path.join(__dirname, 'images')));

// Initialize session
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Set to true if using https
}));

const uri = 'mongodb://localhost:27017/';
const client = new MongoClient(uri);
const dbName = 'avidadb';

async function run() {
    try {
        await client.connect();
        console.log('Connected to MongoDB');
        const database = client.db(dbName);
        const usersCollection = database.collection('acc');
        const eventsCollection = database.collection('events'); // New collection for events

        // Serve the login page
        app.get('/', (req, res) => {
            res.sendFile(path.join(__dirname, 'Webpages/login.html'));
        });

        // API route to handle login
        app.post('/login', async (req, res) => {
            const { email, password } = req.body;
            try {
                const user = await usersCollection.findOne({ email });
                if (user && user.password === password) {
                    // Store user info in the session
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
    } catch (err) {
        console.error(err);
    }
}

run().catch(console.dir);
