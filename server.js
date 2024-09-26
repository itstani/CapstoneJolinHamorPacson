const express = require('express');
const bodyParser = require('body-parser');
const { MongoClient } = require('mongodb');
const path = require('path');

const app = express();
const port = 3000;

// Middleware to parse incoming request bodies
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static files from 'Webpages' and 'images'
app.use(express.static(path.join(__dirname, 'Webpages')));
app.use('/images', express.static(path.join(__dirname, 'images')));

const uri = 'mongodb://localhost:27017/';
const client = new MongoClient(uri);
const dbName = 'avidadb';

async function run() {
    try {
        await client.connect();
        console.log('Connected to MongoDB');
        const database = client.db(dbName);
        const collection = database.collection('acc');

        // Serve the registration page
        app.get('/', (req, res) => {
            res.sendFile(path.join(__dirname, 'Webpages/register.html'));
        });

        // API route to handle registration form submission
        app.post('/register', async (req, res) => {
            const { username, email, password } = req.body;
            try {
                const result = await collection.insertOne({ username, email, password });
                res.json({ message: 'Registration successful', success: true });
            } catch (error) {
                if (error.code === 11000) {
                    res.json({ message: 'Username or email already exists', success: false });
                } else {
                    res.json({ message: 'An error occurred', success: false });
                }
            }
        });

        // API route for login verification
        app.post('/login', async (req, res) => {
            const { email, password } = req.body;

            try {
                // Find the user in the 'acc' collection by email
                const user = await collection.findOne({ email: email });

                if (user) {
                    // Check if the password matches
                    if (user.password === password) {
                        res.json({ message: 'Login successful', success: true });
                    } else {
                        res.json({ message: 'Invalid password', success: false });
                    }
                } else {
                    res.json({ message: 'User not found', success: false });
                }
            } catch (error) {
                res.json({ message: 'An error occurred', success: false });
            }
        });

        app.listen(port, () => {
            console.log(`Server is running on http://localhost:3000`);
        });
    } catch (err) {
        console.error(err);
    }
}

run().catch(console.dir);
