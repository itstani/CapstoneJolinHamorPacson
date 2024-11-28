    require("dotenv").config();
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
    app.use(bodyParser.json());
    app.use(bodyParser.urlencoded({ extended: true }));
    app.use(express.static(path.join(__dirname, "Webpages")));
    app.use("/images", express.static(path.join(__dirname, "images")));
    app.use(cors());
    app.use(
      session({
        secret: "N3$Pxm/mXm1eYY",
        resave: false,
        saveUninitialized: true,
        cookie: { secure: app.get('env') === 'production' },
      })
    );
    
    const storage = multer.diskStorage({
      destination: function (req, file, cb) {
        cb(null, 'uploads/');
      },
      filename: function (req, file, cb) {
        cb(null, Date.now() + path.extname(file.originalname));
      },
    });
    const upload = multer({ storage: storage });
    app.post('/upload-receipt', upload.single('receipt'), async (req, res) => {
      const { eventName, eventDate, amount, startTime, endTime } = req.body;
      const receiptImagePath = req.file ? req.file.path : null;
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
          receiptImage: receiptImagePath,
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
    app.get("/", (req, res) => {
      res.sendFile(path.join(__dirname, "Webpages/login.html"));
    });

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
            const isAdmin = user.email === "admin@gmail.com";
            req.session.user = { username: user.username, email: user.email };

            req.session.save((err) => {
              if (err) {
                console.error("Session save error:", err);
                return res.json({ success: false, message: "Failed to save session." });
              }
              return res.json({
                success: true,
                message: "Login successful",
                username: user.username,
                email: user.email,
                isAdmin,
                redirectUrl: isAdmin ? "../AdHome.html" : "../HoHome.html",
              });
            });
          } else {
            // Invalid password response
            return res.json({ message: "Invalid email or password", success: false });
          }
        } else {
          // Invalid email response
          return res.json({ message: "Invalid email or password", success: false });
        }
      } catch (error) {
        console.error("Error during login:", error);
        return res.json({ message: "An error occurred", success: false });
      }
    });

    app.post("/register", async (req, res) => {
      const { username, lastname, email, password, address, number, landline} = req.body;
      if (!username || !lastname || !email || !password || !address || !number || !landline) {
        return res.json({ message: "Missing required fields", success: false });
      }
      try {
        await client.connect();
        const database = client.db(dbName);
        const usersCollection = database.collection("acc");
        const existingUser = await usersCollection.findOne({ email });
        if (existingUser) {
          return res.json({
            message: "Email already exists. Please choose a different one.",
            success: false,
          });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = {
          username,
          lastname,
          email,
          password: hashedPassword,
          address,
          number,
          landline,
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
    app.post("/updateProfile", async (req, res) => {
      const { firstName, lastName, password } = req.body;

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
        const hashedPassword = await bcrypt.hash(password, 10);
        await client.connect();
        const database = client.db(dbName);
        const usersCollection = database.collection("acc");

        const result = await usersCollection.updateOne(
          { email: req.session.user.email },
          {
            $set: {
              username: `${firstName} ${lastName}`,
              password: hashedPassword,
            },
          }
        );

        if (result.modifiedCount > 0) {
          return res.json({ message: "Profile updated successfully", success: true });
        } else {
          return res.json({ message: "No changes made to the profile", success: false });
        }
      } catch (error) {
        console.error("Error updating profile:", error);
        return res.json({
          message: "An error occurred while updating profile",
          success: false,
        });
      } finally {
        await client.close();
      }
    });

    app.post('/addevent', async (req, res) => {
      const { username, email, hostName, eventName, eventDate, startTime, endTime, amenity, guests, homeownerStatus } = req.body;
      try {
          const start = new Date(`1970-01-01T${startTime}:00`);
          const end = new Date(`1970-01-01T${endTime}:00`);
          const duration = (end - start) / (1000 * 60 * 60);
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
          const db = client.db('avidadb');
          await db.collection('events').insertOne(event);
          req.session.eventData = event;
          res.json({ success: true });
      } catch (error) {
          console.error('Error adding event:', error);
          res.json({ success: false, message: error.message });
      }
    });
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
    app.get('/eventfin', async (req, res) => {
      try {
          await client.connect();
          const database = client.db(dbName);
          const eventsCollection = database.collection('events');
          const events = await eventsCollection.find({}).toArray();
          res.json(events);
      } catch (error) {
          console.error("Error fetching events:", error);
          res.status(500).send('An error occurred while fetching events');
      } finally {
          await client.close();
      }
    });
    app.post("/gcash-payment", async (req, res) => {
      const { amount, eventName, eventDate } = req.body;
      try {
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
      console.log(`Server is running on http://localhost:${port}`);
    });

    app.get('/profile', async (req, res) => {
      if (!req.session.user) {
        return res.json({ success: false, message: "Not logged in" });
      }

      const { email } = req.session.user;
      try {
        await client.connect();
        const database = client.db(dbName);
        const homeownersCollection = database.collection('homeowners');
        const accCollection = database.collection('acc');

        // Fetch user details from acc collection (username and email)
        const accUser = await accCollection.findOne({ email });

        // Fetch additional user details from homeowners collection (first name, last name, etc.)
        const homeownerUser = await homeownersCollection.findOne({ email });

        if (accUser && homeownerUser) {
          return res.json({
            success: true,
            username: accUser.username,
            email: accUser.email,
            firstname: homeownerUser.firstName,
            lastname: homeownerUser.lastName,
            status: homeownerUser.paymentStatus
          });
        } else {
          return res.json({ success: false, message: "User not found in one or both collections" });
        }
      } catch (error) {
        console.error("Error fetching user profile:", error);
        return res.status(500).json({ success: false, message: "Server error" });
      } finally {
        await client.close();
      }
    });

    

    app.post("/updateProfile", async (req, res) => {
      const { newUsername, password } = req.body;
    
      if (!req.session.user) {
        return res.json({
          success: false,
          message: "You must be logged in to update your profile.",
        });
      }
    
      if (!newUsername || newUsername.trim() === "") {
        return res.json({ success: false, message: "Username cannot be empty." });
      }
    
      try {
        await client.connect();
        const database = client.db(dbName);
        const usersCollection = database.collection("acc");
    
        // Update user details
        const updateFields = { username: newUsername };
    
        if (password) {
          const hashedPassword = await bcrypt.hash(password, 10);
          updateFields.password = hashedPassword;
        }
    
        const result = await usersCollection.updateOne(
          { email: req.session.user.email },
          { $set: updateFields }
        );
    
        if (result.modifiedCount > 0) {
          res.json({ success: true, message: "Profile updated successfully." });
        } else {
          res.json({ success: false, message: "No changes made to the profile." });
        }
      } catch (error) {
        console.error("Error updating profile:", error);
        res.json({
          success: false,
          message: "An error occurred while updating profile.",
        });
      } finally {
        await client.close();
      }
    });
    
    
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
        await client.connect();
        await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
      } finally {
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
          const collection = database.collection('homeowners');
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

    app.patch('/toggleStatus/:username/:lastname', async (req, res) => {
      const { username, lastname } = req.params;

      try {
        await client.connect();
        const database = client.db(dbName);
        const collection = database.collection('acc');

        const user = await collection.findOne({ username, lastname });
        if (!user) {
          return res.status(404).json({ success: false, message: 'User not found' });
        }

        const newStatus = user.status === 'Paid' ? 'Unpaid' : 'Paid';
        await collection.updateOne({ username, lastname }, { $set: { status: newStatus } });

        return res.status(200).json({ success: true, status: newStatus });
      } catch (error) {
        console.error('Error toggling status:', error);
        return res.status(500).json({ success: false, message: 'Server error' });
      } finally {
        await client.close();
      }
    });


