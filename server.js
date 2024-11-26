require("dotenv").config(); // Load environment variables from .env file
const express = require("express");
const bodyParser = require("body-parser");
const { MongoClient, ServerApiVersion } = require("mongodb");
const multer = require('multer');
const path = require('path');
const session = require("express-session");
const bcrypt = require("bcryptjs");
const cors = require('cors');



const app = express();
const port = 3000;
const dbName = "avidadb";
const uri = "mongodb+srv://ethan:Edj1026@avidadb.upica.mongodb.net/?retryWrites=true&w=majority&appName=avidadb";
// Create a MongoClient with a MongoClientOptions object to set the Stable API version
//const uri = 'mongodb://localhost:27017/';
//const client = new MongoClient(uri);
//const dbName = 'avidadb';

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});
// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "Webpages")));
app.use("/images", express.static(path.join(__dirname, "images")));
app.use(cors());

// Session setup
app.use(
  session({
    secret: "N3$Pxm/mXm1eYY", // Change this to a secure key
    resave: false,
    saveUninitialized: true,
    cookie: { secure: true }, // Set to true if using https
  })
);

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/'); // Folder to save the uploaded files
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + path.extname(file.originalname)); // Generate a unique filename
  },
});

const upload = multer({ storage: storage });

app.post('/upload-receipt', upload.single('receipt'), async (req, res) => {
  const { eventName, eventDate, amount, startTime, endTime } = req.body;
  const receiptImagePath = req.file ? req.file.path : null; // Get the uploaded file path

  // Save payment details in the database
  try {
    await client.connect();
    const db = client.db(dbName);
    const paymentsCollection = db.collection('eventPayments');

    const paymentDetails = {
      eventName,
      eventDate,
      startTime,
      endTime,
      amount,
      receiptImage: receiptImagePath, // Save receipt file path
    };

    await paymentsCollection.insertOne(paymentDetails);

    res.json({ success: true, message: 'Payment details saved successfully!' });
  } catch (error) {
    console.error('Error saving payment details:', error);
    res.json({ success: false, message: 'Error saving payment details' });
  } finally {
    await client.close();
  }
});

// Serve the login page
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "Webpages/login.html"));
});

// API route to handle manual login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    await client.connect();
    const database = client.db(dbName);
    const usersCollection = database.collection("acc");
    const user = await usersCollection.findOne({ email });

    if (user) {
      const isPasswordValid = await bcrypt.compare(password, user.password);

      if (isPasswordValid) {
        const isAdmin = user.email === "admin@gmail.com"; // Check if the user is admin
        req.session.user = { username: user.username, email: user.email };
        
        res.json({
          message: "Login successful",
          success: true,
          username: user.username,
          email: user.email,
          isAdmin,
          redirectUrl: isAdmin ? "../main.html" : "../welcome.html" // Set redirect URL based on role
        });
      } else {
        res.json({ message: "Invalid email or password", success: false });
      }
    } else {
      res.json({ message: "Invalid email or password", success: false });
    }
  } catch (error) {
    console.error("Error during login:", error);
    res.json({ message: "An error occurred", success: false });
  }
});

// API route to handle user registration
app.post('/register', async (req, res) => {
  const { username,lastname,email,password,address,number,landline } = req.body;

  // Validate input data
  if (!username || !lastname || !email || !password || !address || !number) {
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
          address,
          number,
          landline, 
          status: "Paid", //homeowner monthly status to be verified by admin if paid or not
          createdAt: new Date(),
      };
      await usersCollection.insertOne(newUser);

      res.json({ message: 'Registration successful', success: true });
  } catch (error) {
      console.error("Error during registration:", error);
      res.json({ message: 'Registration failed', success: false });
  }
});

// API route to handle profile update
app.post("/updateProfile", async (req, res) => {
  const { firstName, lastName, password } = req.body;

  // Check if user is logged in
  if (!req.session.user) {
    return res.json({
      message: "You must be logged in to update your profile",
      success: false,
    });
  }

  if (!firstName || !lastName || !password) {
    return res.json({ message: "Missing required fields", success: false });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10); // Hash the new password

    await client.connect();
    const database = client.db(dbName);
    const usersCollection = database.collection("acc");

    // Update the user's profile in the database
    const result = await usersCollection.updateOne(
      { email: req.session.user.email }, // Find the user by their email
      {
        $set: {
          username: `${firstName} ${lastName}`, // Update username with the new first and last name
          password: hashedPassword, // Update password with the hashed password
        },
      }
    );

    if (result.modifiedCount > 0) {
      res.json({ message: "Profile updated successfully", success: true });
    } else {
      res.json({ message: "No changes made to the profile", success: false });
    }
  } catch (error) {
    console.error("Error updating profile:", error);
    res.json({
      message: "An error occurred while updating profile",
      success: false,
    });
  } finally {
    await client.close();
  }
});
// Store event data in session
app.post('/addevent', async (req, res) => {
  const { username, email, hostName, eventName, eventDate, startTime, endTime, amenity, guests, homeownerStatus } = req.body;

  try {
      // Calculate duration based on startTime and endTime
      const start = new Date(`1970-01-01T${startTime}:00`);
      const end = new Date(`1970-01-01T${endTime}:00`);
      const duration = (end - start) / (1000 * 60 * 60); // Duration in hours

      const event = {
          username,
          email,
          hostName,
          eventName,
          eventDate,
          startTime,
          endTime,
          duration,
          amenity,
          guests,
          homeownerStatus
      };

      // Insert the event into the 'events' collection of 'avidadb'
      const db = client.db('avidadb'); // Ensure client is connected
      await db.collection('events').insertOne(event);

      // Store the event data in session to be accessed in the next page
      req.session.eventData = event;

      res.json({ success: true });
  } catch (error) {
      console.error('Error adding event:', error);
      res.json({ success: false, message: error.message });
  }
});




// Endpoint to delete the most recent event
app.post("/delEvent", async (req, res) => {
  const { username } = req.body;

  try {
    await client.connect();
    const database = client.db(dbName);
    const eventsCollection = database.collection("events");

    const result = await eventsCollection.findOneAndDelete(
      { "createdBy.username": username },
      { sort: { createdAt: -1 } }
    );

    if (result.value) {
      res.json({
        success: true,
        message: "Most recent event deleted successfully.",
      });
    } else {
      res.json({ success: false, message: "Cancelled" });
    }
  } catch (error) {
    console.error("Error deleting recent event:", error);
    res
      .status(500)
      .json({ success: false, message: "Error deleting recent event." });
  } finally {
    await client.close();
  }
});

// Route to display all events
app.get('/eventfin', async (req, res) => {
  try {
      await client.connect();
      const database = client.db(dbName);
      const eventsCollection = database.collection('events');

      const events = await eventsCollection.find({}).toArray();

      res.json(events); // Send the events data as JSON
  } catch (error) {
      console.error("Error fetching events:", error);
      res.status(500).send('An error occurred while fetching events');
  } finally {
      await client.close();
  }
});


// Simulated GCash payment endpoint
app.post("/gcash-payment", async (req, res) => {
  const { amount, eventName, eventDate } = req.body;

  try {
    // In production, here would be the API call to GCash
    // This is a simulation of a successful payment response
    res.json({
      success: true,
      message: "Payment processed successfully with GCash",
    });
  } catch (error) {
    console.error("Error during GCash payment simulation:", error);
    res.json({ success: false, message: "Payment failed. Please try again." });
  }
});
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`); // Corrected the string interpolation
});
// Endpoint to fetch user profile
app.get("/profile", async (req, res) => {
  if (!req.session.user) {
    return res.json({ success: false, message: "Not logged in" });
  }

  const { email } = req.session.user;

  try {
    await client.connect();
    const database = client.db(dbName);
    const usersCollection = database.collection("acc");

    // Fetch user data from the database
    const user = await usersCollection.findOne({ email });

    if (user) {
      return res.json({
        success: true,
        username: user.username,
        lastname: user.lastname,
        email: user.email,
      });
    } else {
      return res.json({ success: false, message: "User not found" });
    }
  } catch (error) {
    console.error("Error fetching user profile:", error);
    return res.status(500).json({ success: false, message: "Server error" });
  } finally {
    await client.close();
  }
});
// API route to update username
app.post("/updateUsername", async (req, res) => {
  const { newUsername } = req.body;

  // Check if the user is logged in
  if (!req.session.user) {
    return res.json({
      success: false,
      message: "You must be logged in to update your profile.",
    });
  }

  // Validate the new username (make sure it's not empty)
  if (!newUsername) {
    return res.json({ success: false, message: "New username is required." });
  }

  try {
    const { email } = req.session.user;

    // Check if the new username already exists in the database
    await client.connect();
    const database = client.db(dbName);
    const usersCollection = database.collection("acc");

    const existingUser = await usersCollection.findOne({
      username: newUsername,
    });
    if (existingUser) {
      return res.json({
        success: false,
        message: "Username already taken. Please choose a different username.",
      });
    }

    // Update the username in the database
    const result = await usersCollection.updateOne(
      { email },
      { $set: { username: newUsername } }
    );

    if (result.modifiedCount > 0) {
      // Update the session with the new username
      req.session.user.username = newUsername;

      res.json({ success: true, message: "Username updated successfully." });
    } else {
      res.json({
        success: false,
        message: "No changes made. Please try again.",
      });
    }
  } catch (error) {
    console.error("Error updating username:", error);
    res.status(500).json({
      success: false,
      message: "An error occurred while updating the username.",
    });
  } finally {
    await client.close();
  }
});

// Route to fetch approved events
app.get('/approved-events', async (req, res) => {
  try {
      console.log("Connecting to MongoDB...");
      await client.connect();

      const db = client.db(dbName);
      console.log("Connected to DB:", dbName);

      const eventsCollection = db.collection('aevents');
      const events = await eventsCollection.find({ status: 'approved' }).toArray();
      
      res.json({ success: true, events });
  } catch (error) {
      console.error("Error fetching approved events:", error);
      res.status(500).json({ success: false, message: "Error fetching events" });
  } finally {
      await client.close();
      console.log("MongoDB connection closed.");
  }
});



// Logout endpoint to clear session
app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Failed to destroy session:', err);
      return res.status(500).json({ message: 'Failed to log out' });
    }
    res.status(200).json({ message: 'Logout successful' });
  });
});


async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();
    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
    await client.close();
  }
}
run().catch(console.dir);

//get data from acc collection to display in homeowner table hotable.html
app.get('/getHomeowners', async (req, res) => {
  const client = new MongoClient(uri);
  try {
      await client.connect();
      const database = client.db('avidadb');
      const collection = database.collection('acc');
      
      //fetch all homeowners in dtb
      const homeowners = await collection.find().toArray();

      
      res.json(homeowners);
  } catch (error) {
      console.error('Error fetching data:', error);
      res.status(500).json({ error: 'Failed to fetch data' });
  } finally {
      await client.close(); 
  }
});

//---------------------------------------------------------------------------------Hotable.html--------------------------
// Route to toggle the payment status
app.patch('/toggleStatus/:username/:lastname', async (req, res) => {
  const client = new MongoClient(uri);
  const { username, lastname } = req.params; 
  try {
      await client.connect();
      const database = client.db('avidadb');
      const collection = database.collection('acc');

      // Find the user by username and lastname
      const user = await collection.findOne({ username, lastname });

      if (!user) {
          return res.status(404).send('User not found');
      }

      //status toggle paid to unpaid vvise vversa
      let newStatus;

      if (user.status === 'Paid') {
          newStatus = 'Unpaid';
      } else if (user.status !== 'Paid') {
          newStatus = 'Paid';
      }

      // Update the status
      await collection.updateOne(
          { username, lastname },
          { $set: { status: newStatus } }
      );

      // Send the new status as a response
      res.status(200).send({ status: newStatus });
  } catch (error) {
      console.error('Error toggling status:', error);
      res.status(500).send('Server error');
  } finally {
      await client.close();
  }
});
//---------------------------------------------------------------------------------Hotable.html--------------------------

