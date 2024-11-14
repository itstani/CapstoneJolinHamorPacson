require("dotenv").config(); // Load environment variables from .env file
const express = require("express");
const bodyParser = require("body-parser");
const { MongoClient } = require("mongodb");
const path = require("path");
const session = require("express-session");
const bcrypt = require("bcryptjs");

const app = express();
const port = 3000;

const uri = "mongodb://localhost:27017/";
const client = new MongoClient(uri);
const dbName = "avidadb";

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "Webpages")));
app.use("/images", express.static(path.join(__dirname, "images")));

// Session setup
app.use(
  session({
    secret: "your-secret-key", // Change this to a secure key
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }, // Set to true if using https
  })
);

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
      // Compare the entered password with the stored hashed password
      const isPasswordValid = await bcrypt.compare(password, user.password);

      if (isPasswordValid) {
        const isAdmin = user.email === "admin@example.com"; // Check if the user is admin
        req.session.user = { username: user.username, email: user.email };
        res.json({
          message: "Login successful",
          success: true,
          username: user.username,
          email: user.email,
          isAdmin,
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
app.post("/register", async (req, res) => {
  const { username, lastname, email, password } = req.body;
  if (!username || !lastname || !email || !password) {
    return res.json({ message: "Missing required fields", success: false });
  }

  try {
    await client.connect();
    const database = client.db(dbName);
    const usersCollection = database.collection("acc");

    // Check if user already exists
    const existingUser = await usersCollection.findOne({ email });
    if (existingUser) {
      return res.json({
        message: "Email already exists. Please choose a different one.",
        success: false,
      });
    }

    // Hash the password before saving it
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user
    const newUser = {
      username,
      lastname,
      email,
      password: hashedPassword,
    };

    await usersCollection.insertOne(newUser);
    res.json({ message: "Registration successful", success: true });
  } catch (error) {
    console.error("Error during registration:", error);
    res.json({ message: "An error occurred", success: false });
  } finally {
    await client.close();
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
app.get("/eventfin", async (req, res) => {
  try {
    await client.connect();
    const database = client.db(dbName);
    const eventsCollection = database.collection("events");
    const events = await eventsCollection.find({}).toArray();

    res.render("eventfin", { events });
  } catch (error) {
    console.error("Error fetching events:", error);
    res.status(500).send("An error occurred while fetching events");
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

// Logout endpoint to clear session
app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res
        .status(500)
        .json({ success: false, message: "Error during logout" });
    }
    res.json({ success: true });
  });
});
