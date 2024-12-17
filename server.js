      require("dotenv").config();
      const express = require("express");
      const bodyParser = require("body-parser");
      const multer = require('multer');
      const path = require('path');
      const session = require("express-session");
      const bcrypt = require("bcryptjs");
      const cors = require('cors');
      const fs = require('fs');
      const { ObjectId } = require('mongodb');
      const { MongoClient, ServerApiVersion } = require("mongodb");


      const app = express();
      const port = 3000;
      const dbName = "avidadb";
      const uri = "mongodb+srv://ethan:Edj1026@avidadb.upica.mongodb.net/?retryWrites=true&w=majority&appName=avidadb";
      let client;
      let database;
      let activityLogsCollection; // Declare activityLogsCollection here

      async function connectToDatabase() {
        if (!client) {
          client = new MongoClient(uri, {
            serverApi: {
              version: ServerApiVersion.v1,
              strict: true,
              deprecationErrors: true,
            }
          });
          
          try {
            await client.connect();
            console.log("Connected to MongoDB!");
            database = client.db(dbName);
            activityLogsCollection = database.collection('activityLogs'); // Initialize activityLogsCollection after connecting to the database
          } catch (err) {
            console.error("Error connecting to MongoDB:", err);
            throw err;
          }
        }
        return database;
      }

      app.use(bodyParser.json());
      app.use(bodyParser.urlencoded({ extended: true }));
      app.use(express.static(path.join(__dirname, "Webpages")));
      app.use("/CSS", express.static(path.join(__dirname,"CSS")));
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
      // Database connection setup
          

      // Middleware to attach the database
      app.use(async (req, res, next) => {
        try {
          req.db = await connectToDatabase();
          next();
        } catch (error) {
          console.error("Database connection error:", error);
          res.status(500).json({ error: "Internal server error" });
        }
      });
          


      const uploadsDir = path.join(__dirname, 'uploads');
      if (!fs.existsSync(uploadsDir)){
          fs.mkdirSync(uploadsDir, { recursive: true });
      }

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
        try {
          if (!req.file) {
            return res.status(400).json({ 
              success: false, 
              message: 'No file uploaded' 
            });
          }
      
          // Read the uploaded file
          const filePath = req.file.path;
          const fileBuffer = fs.readFileSync(filePath);
      
          // Convert the file to Base64
          const base64Image = fileBuffer.toString('base64');
          const mimeType = req.file.mimetype;
      
          // Construct the MongoDB document
          const paymentData = {
            userEmail: req.body.userEmail, // Include userEmail in the payment data
            eventName: req.body.eventName,
            eventDate: req.body.eventDate,
            amount: req.body.finalAmount,
            startTime: req.body.startTime,
            endTime: req.body.endTime,
            paymentMethod: req.body.paymentMethod,
            receiptImage: `data:${mimeType};base64,${base64Image}`,
            timestamp: new Date()
          };
      
          // Save to MongoDB
          const db = await client.db(dbName); 
          const paymentsCollection = db.collection('eventpayments');
          await paymentsCollection.insertOne(paymentData);
      
          // Cleanup the temporary file
          fs.unlinkSync(filePath);
      
          res.status(200).json({ 
            success: true, 
            message: "Receipt uploaded and payment processed successfully!" 
          });
        } catch (err) {
          console.error("Error handling receipt upload:", err);
          // Cleanup the temporary file if it exists
          if (req.file && req.file.path) {
            try {
              fs.unlinkSync(req.file.path);
            } catch (unlinkErr) {
              console.error("Error deleting temporary file:", unlinkErr);
            }
          }
          res.status(500).json({ 
            success: false, 
            message: "Error processing payment. Please try again." 
          });
        }
      });
          
      app.get("/", (req, res) => {
        res.sendFile(path.join(__dirname, "Webpages/login.html"));
      });

          
      app.post("/login", async (req, res) => {
        const { login, password } = req.body;
    
        try {
            const usersCollection = req.db.collection("acc");
            const user = await usersCollection.findOne({
                $or: [
                    { email: { $regex: new RegExp(`^${login}$`, 'i') } },
                    { username: { $regex: new RegExp(`^${login}$`, 'i') } }
                ]
            });
    
            if (user) {
                const isPasswordValid = await bcrypt.compare(password, user.password);
                if (isPasswordValid) {
                    req.session.user = {
                        id: user._id,
                        username: user.username,
                        email: user.email
                    };
                    
                    res.json({
                        success: true,
                        username: user.username,
                        email: user.email,
                        redirectUrl: user.role === 'admin' ? '../AdHome.html' : '../HoHome.html',
                    });
                } else {
                    res.status(401).json({ success: false, message: 'Invalid credentials' });
                }
            } else {
                res.status(401).json({ success: false, message: 'Invalid credentials' });
            }
        } catch (error) {
            console.error("Error during login:", error);
            res.status(500).json({ success: false, message: 'Server error' });
        }
    });
          
      app.get("/check-existence", async (req, res) => {
      const { field, value } = req.query;
          
      try {
        const db = await connectToDatabase();
        const usersCollection = db.collection("acc");
        
        const query = { [field]: value };
        const existingUser = await usersCollection.findOne(query);
        
        res.json({ exists: !!existingUser });
      } catch (error) {
        console.error("Error checking existence:", error);
        res.status(500).json({ error: "An error occurred" });
      }
      });
        
      app.post("/register", async (req, res) => {
      const { username, email, password } = req.body;
      if (!username || !email || !password) {
        return res.json({ message: "Missing required fields", success: false });
      }
      try {
        const db = await connectToDatabase();
        const usersCollection = db.collection("acc");
        
        const existingUser = await usersCollection.findOne({ $or: [{ username }, { email }] });
        if (existingUser) {
          return res.json({
            message: "Username or email already exists. Please choose different ones.",
            success: false,
          });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = {
          username,
          email,
          password: hashedPassword,
        };
        
        await usersCollection.insertOne(newUser);
        
        res.json({ message: "Registration successful", success: true });
      } catch (error) {
        console.error("Error during registration:", error);
        res.json({ message: "An error occurred", success: false });
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
          const db = await connectToDatabase();

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
            await logActivity('profileUpdate', `User ${req.session.user.email} updated their profile`); // Log activity
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
        }
      });

      app.get('/api/user-info', (req, res) => {
        if (!req.session || !req.session.user || !req.session.user.email) {
            return res.status(401).json({
                success: false,
                message: 'User not authenticated'
            });
        }
    
        res.json({
            success: true,
            email: req.session.user.email
        });
    });
    
    // Update the existing addevent endpoint
    app.post('/addevent', async (req, res) => {
      if (!req.session || !req.session.user || !req.session.user.email) {
          return res.status(401).json({
              success: false,
              message: 'User not authenticated'
          });
      }
  
      const { hostName, eventName, eventDate, startTime, endTime, amenity, guests, homeownerStatus } = req.body;
      const userEmail = req.session.user.email; // Get email from session
  
      try {
          const db = await connectToDatabase();
          const eventsCollection = db.collection('events');
  
          // Add event to database with user's email
          const newEvent = {
              hostName,
              userEmail, // Include the user's email
              eventName,
              eventDate,
              startTime,
              endTime,
              amenity,
              guests,
              homeownerStatus,
              createdAt: new Date()
          };
  
          await eventsCollection.insertOne(newEvent);
          
          res.status(201).json({ 
              success: true, 
              message: "Event created successfully." 
          });
      } catch (error) {
          console.error('Error creating event:', error);
          res.status(500).json({ 
              success: false, 
              message: "An error occurred while creating the event." 
          });
      }
  });
    


      app.post("/delEvent", async (req, res) => {
        const { username } = req.body;
        try {
          const db = await connectToDatabase();

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
        }
      });
      app.get('/eventfin', async (req, res) => {
        try {
          const db = await connectToDatabase();

            const database = client.db(dbName);
            const eventsCollection = database.collection('events');
            const events = await eventsCollection.find({}).toArray();
            res.json(events);
        } catch (error) {
            console.error("Error fetching events:", error);
            res.status(500).send('An error occurred while fetching events');
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
      app.listen(port, (err) => {
        if (err) {
          console.error("Failed to start server:", err.message);
          process.exit(1);
        }
        console.log(`Server is running on http://localhost:${port}`);
      });
          


          app.get('/profile', async (req, res) => {

            if (!req.session.user) {
              return res.json({ success: false, message: "Not logged in" });
            }
            const { email } = req.session.user;
            try {
              const db = await connectToDatabase();
              const database = client.db(dbName);
              const homeownersCollection = database.collection('homeowners');
              const accCollection = database.collection('acc');
              const accUser = await accCollection.findOne({ email });
              const homeownerUser = await homeownersCollection.findOne({ email });

              if (accUser && homeownerUser) {

                return res.json({

                  success: true,
                  success: true,
                  username: req.session.user.username,
                  email: req.session.user.email,
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
            }
          });




          
          
      app.get('/approved-events', async (req, res, next) => {
        try {
            const db = await connectToDatabase();
            const eventsCollection = db.collection('aevents');
            const events = await eventsCollection.find({ status: 'approved' }).toArray();
            res.json({ success: true, events });
        } catch (error) {
            next(error);
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
          await connectToDatabase();
          console.log("Pinged your deployment. You successfully connected to MongoDB!");
        } catch (error) {
          console.error("Error connecting to MongoDB:", error);
        }
      }
      run().catch(console.dir);
          


      //get data from acc collection to display in homeowner table hotable.html
      app.get('/getHomeowners', async (req, res) => {
        try {
          const db = await connectToDatabase();
          const collection = db.collection('homeowners');
          const homeowners = await collection.find().toArray();
          res.json(homeowners);
        } catch (error) {
          console.error('Error fetching data:', error);
          res.status(500).json({ error: 'Failed to fetch data' });
        }
      });
          


      app.put('/updateHomeowner/:email', async (req, res) => {
        const { email } = req.params;
        const updateData = req.body;

        try {
            const db = await connectToDatabase();

            const database = client.db('avidadb');
            const collection = database.collection('homeowners');

            // Retrieve the homeowner's document to get the last name
            const homeowner = await collection.findOne({ email: email });

            if (!homeowner) {
                return res.json({ success: false, message: 'Homeowner not found' });
            }

            const result = await collection.updateOne(
                { email: email },
                { $set: updateData }
            );

            if (result.modifiedCount > 0) {
                const lastName = homeowner.lastName; // Assuming 'lastName' is the field storing the last name
                await logActivity('homeownerUpdate', `Homeowner with Last Name ${lastName} updated`); // Log activity
                res.json({ success: true, message: 'Homeowner updated successfully' });
            } else {
                res.json({ success: false, message: 'No document matched the query' });
            }
        } catch (error) {
            console.error('Error updating homeowner:', error);
            res.status(500).json({ success: false, error: 'Failed to update homeowner' });
        }
      });
        
        
        
      app.get('/pending-events', async (req, res) => {
        try {
          const db = await connectToDatabase();
          const eventpaymentsCollection = db.collection('eventpayments');
          const pendingEvents = await eventpaymentsCollection.find({ status: { $ne: 'approved' } }).toArray();
          res.json({ success: true, events: pendingEvents });
        } catch (error) {
          console.error('Error fetching pending events:', error);
          res.status(500).json({ success: false, message: 'Error fetching events' });
        }
      });
        
      // Update the existing approve event route
      app.put('/approveEvent/:eventName', async (req, res) => {
        const { eventName } = req.params;
      
        try {
          const db = await connectToDatabase();
          const eventpaymentsCollection = db.collection('eventpayments');
          const eventsCollection = db.collection('events');
          const aeventsCollection = db.collection('aevents');
      
          const event = await eventsCollection.findOne({ eventName });
      
          if (event) {
            const approvedAt = new Date();
            const approvedEvent = await aeventsCollection.insertOne({ ...event, status: 'approved', approvedAt });
            await eventsCollection.deleteOne({ eventName });
            await eventpaymentsCollection.updateOne(
              { eventName: event.eventName },
              { $set: { status: 'approved', approvedAt } }
            );
            await logActivity('eventApproval', `Event ${eventName} approved`);
      
            // Create a notification for the event approval
            await createNotification(
              event.userEmail, // Use userEmail instead of hostName
              'event',
              `Your event "${event.eventName}" has been approved!`,
              approvedEvent.insertedId
            );
      
            res.json({ success: true, message: 'Event approved and moved to approved events.' });
          } else {
            res.status(404).json({ success: false, message: 'Event not found in events collection.' });
          }
        } catch (error) {
          console.error('Error approving event:', error);
          res.status(500).json({ success: false, message: 'Server error while approving event.' });
        }
      });
      




      app.post('/disapprove-event', async (req, res) => {
        const { eventName, reason } = req.body;

        try {
            const db = await connectToDatabase();
            const eventpaymentsCollection = db.collection('eventpayments');
            const eventsCollection = db.collection('events');
            const deventsCollection = db.collection('devents'); // Disapproved events collection

            // Fetch event from the events collection
            const event = await eventsCollection.findOne({ eventName });

            if (event) {
                // Move event to devents collection
                await deventsCollection.insertOne({ ...event, disapprovalReason: reason });

                // Remove from events collection
                await eventsCollection.deleteOne({ eventName });

                // Update status to 'disapproved' in eventpayments collection with reason
                await eventpaymentsCollection.updateOne(
                    { eventName },
                    { $set: { status: 'disapproved', disapprovalReason: reason } }
                );
                await logActivity('eventDisapproval', `Event ${eventName} disapproved. Reason: ${reason}`); // Log activity
                res.json({ success: true, message: 'Event disapproved and moved to disapproved events.' });
            } else {
                res.status(404).json({ success: false, message: 'Event not found in events collection.' });
            }
        } catch (error) {
            console.error('Error disapproving event:', error);
            res.status(500).json({ success: false, message: 'Server error while disapproving event.' });
        }
      });



        
      app.get('/receipt-image', async (req, res) => {
        const { eventName, eventDate } = req.query;

        try {
            const eventpaymentsCollection = req.db.collection('eventpayments');
            const eventsCollection = req.db.collection('events');

            // Fetch from `eventpayments` collection
            const paymentEvent = await eventpaymentsCollection.findOne({ eventName, eventDate });

            // Fetch from `events` collection
            const eventDetails = await eventsCollection.findOne({ eventName, eventDate });

            if (paymentEvent) {
                // Combine startTime and endTime if they exist
                const combinedTime = eventDetails?.startTime && eventDetails?.endTime
                    ? `${eventDetails.startTime} - ${eventDetails.endTime}`
                    : null;

                res.json({
                    success: true,
                    receiptImage: paymentEvent.receiptImage || null,
                    paymentDetails: paymentEvent,
                    eventDetails: eventDetails
                        ? {
                            ...eventDetails,
                            combinedTime, // Add the combined time to the event details
                        }
                        : null,
                });
            } else {
                res.json({
                    success: false,
                    message: 'Receipt image or event details not found',
                });
            }
        } catch (error) {
            console.error('Error fetching receipt image or event details:', error);
            res.status(500).json({ success: false, message: 'Server error' });
        }
      });


      //Submit Concern
      app.post('/addconcern', async (req, res) => {
      const { username, email, subject, message } = req.body;

      try {   
        const createdAt = new Date();  

        const concern = {
          username,
          email,
          subject,
          message,
          createdAt,
          status: 'new'  // Add this line
        };

        const db = client.db('avidadb');
        await db.collection('Concerns').insertOne(concern);
        

        
        res.json({ success: true });
      } catch (error) {
        console.error('Error adding concern:', error);
        res.json({ success: false, message: error.message });
      }
      });


      //Concern Table
      app.get('/getConcerns', async (req, res) => {
      try {
        const db = await connectToDatabase();
        const collection = db.collection('Concerns');
        const page = parseInt(req.query.page) || 1;
        const limit = 5;
        const skip = (page - 1) * limit;

        const totalConcerns = await collection.countDocuments();
        const concerns = await collection.find()
          .sort({ createdAt: -1 })
          .skip(skip)
          .limit(limit)
          .toArray();

        res.json({
          concerns,
          currentPage: page,
          totalPages: Math.ceil(totalConcerns / limit)
        });
      } catch (error) {
        console.error('Error fetching concerns:', error);
        res.status(500).json({ error: 'Failed to fetch concerns' });
      }
      });

      process.on('SIGINT', async () => {
        console.log('Shutting down server...');
        if (client) {
          await client.close();
          console.log('MongoDB client closed.');
        }
        process.exit(0);
      });
      //recent activity logs
      app.get('/getRecentActivity', async (req, res) => {
      try {
        const page = parseInt(req.query.page) || 1;
        const limit = 5; 
        const skip = (page - 1) * limit;

        const totalActivities = await activityLogsCollection.countDocuments();
        const recentActivity = await activityLogsCollection
          .find({})
          .sort({ timestamp: -1 })
          .skip(skip)
          .limit(limit)
          .toArray();

        res.json({
          activities: recentActivity,
          totalPages: Math.ceil(totalActivities / limit),
          currentPage: page
        });
      } catch (error) {
        console.error('Error fetching recent activity:', error);
        res.status(500).json({ error: 'Failed to fetch recent activity' });
      }
      });

      async function logActivity(action, details) {
      try {
        await activityLogsCollection.insertOne({
          action,
          details,
          timestamp: new Date()
        });
      } catch (error) {
        console.error('Error logging activity:', error);
      }
      }

      app.get('/getUpcomingEvents', async (req, res) => {
      try {
        const db = await connectToDatabase();
        const eventsCollection = db.collection('aevents');
        
        const page = parseInt(req.query.page) || 1;
        const limit = 5;
        const skip = (page - 1) * limit;

        // Get the current date
        const currentDate = new Date();
        
        // Find events that are upcoming (event date is greater than or equal to the current date)
        const totalEvents = await eventsCollection.countDocuments({
          eventDate: { $gte: currentDate.toISOString().split('T')[0] }
        });

        const upcomingEvents = await eventsCollection.find({
          eventDate: { $gte: currentDate.toISOString().split('T')[0] }
        }).sort({ eventDate: 1 }).skip(skip).limit(limit).toArray();

        res.json({
          events: upcomingEvents,
          currentPage: page,
          totalPages: Math.ceil(totalEvents / limit)
        });
      } catch (error) {
        console.error('Error fetching upcoming events:', error);
        res.status(500).json({ error: 'Failed to fetch upcoming events' });
      }
      });



      app.get('/getCurrentlyReservedAmenities', async (req, res) => {
      try {
        const db = await connectToDatabase();
        const reservationsCollection = db.collection('aevents');
        
        // Get the current date in YYYY-MM-DD format
        const currentDate = new Date().toISOString().split('T')[0];
        
        // Find reservations for today
        const reservations = await reservationsCollection.find({
          eventDate: currentDate,
          status: 'approved'
        }).toArray();

        console.log('Reservations found:', reservations); // Debug log

        // Extract unique amenities from today's reservations
        const uniqueAmenities = [...new Set(reservations.map(r => r.amenity))];

        // Create an array of amenity objects with image paths
        const amenities = uniqueAmenities.map(amenity => ({
          name: amenity,
          imagePath: getAmenityImagePath(amenity)
        }));

        console.log('Amenities to be sent:', amenities); // Debug log

        res.json(amenities);
      } catch (error) {
        console.error('Error fetching currently reserved amenities:', error);
        res.status(500).json({ error: 'Failed to fetch currently reserved amenities' });
      }
      });
      // Helper function to get the image path for each amenity
      function getAmenityImagePath(amenityName) {
      switch (amenityName.toLowerCase()) {
        case 'clubhouse':
          return 'images/clubhouseimg.jpg';
        case 'court':
          return 'images/Courtimg.jpg';
        case 'pool':
          return 'images/poolimg.png';
        default:
          return 'images/placeholder.jpg';
      }
      }

      app.post('/resolveConcern/:id', async (req, res) => {
      try {
        const { id } = req.params;
        const db = await connectToDatabase();
        const concernsCollection = db.collection('Concerns');
        
        const result = await concernsCollection.deleteOne({ _id: new ObjectId(id) });
        
        if (result.deletedCount === 1) {
          await logActivity('concernResolved', `Concern with ID ${id} resolved and deleted`);
          res.json({ success: true, message: 'Concern resolved successfully' });
        } else {
          res.json({ success: false, message: 'Concern not found' });
        }
      } catch (error) {
        console.error('Error resolving concern:', error);
        res.status(500).json({ success: false, message: 'Server error' });
      }
      });

      app.put('/updateConcernStatus/:id', async (req, res) => {
        const { id } = req.params;
        const { status } = req.body;
      
        try {
          const db = await connectToDatabase();
          const concernsCollection = db.collection('Concerns');
          
          const updatedAt = new Date();
          const result = await concernsCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: { status: status, updatedAt } }
          );
          
          if (result.modifiedCount === 1) {
            await logActivity('concernStatusUpdate', `Concern status updated to ${status}`);
      
            // Fetch the updated concern to get the user's email
            const updatedConcern = await concernsCollection.findOne({ _id: new ObjectId(id) });
      
            // Create a notification for the concern status update
            if (updatedConcern) {
              await createNotification(
                updatedConcern.email,
                'concern',
                `Your concern "${updatedConcern.subject}" has been ${status}.`,
                updatedConcern._id
              );
            }
      
            res.json({ success: true, message: 'Concern status updated successfully' });
          } else {
            res.json({ success: false, message: 'Concern not found or status not changed' });
          }
        } catch (error) {
          console.error('Error updating concern status:', error);
          res.status(500).json({ success: false, message: 'Server error' });
        }
      });

      app.get('/api/notifications', async (req, res) => {
        try {
          const userEmail = req.session?.user?.email;
          
          console.log('Fetching notifications for user:', userEmail);
      
          if (!userEmail) {
            console.log('No user email found in session');
            return res.status(401).json({ 
              success: false, 
              error: 'User not authenticated',
              notifications: [],
              unreadCount: 0
            });
          }
      
          const db = await connectToDatabase();
          const notificationsCollection = db.collection('notifications');
      
          console.log('Connected to database, fetching notifications...');
      
          // Fetch notifications for this user
          const notifications = await notificationsCollection.find({
            userEmail: userEmail, // This should now correctly use the user's email from the session
            read: false
          }).sort({ timestamp: -1 }).limit(10).toArray();
      
          console.log('Found notifications:', notifications.length);
      
          res.json({
            success: true,
            notifications: notifications,
            unreadCount: notifications.length
          });
        } catch (error) {
          console.error('Error fetching notifications:', error);
          res.status(500).json({ 
            success: false, 
            error: 'Internal server error',
            notifications: [],
            unreadCount: 0
          });
        }
      });
      
      

      app.post('/api/markNotificationsAsRead', async (req, res) => {
        try {
          const userEmail = req.session?.user?.email;
          const { notificationIds } = req.body;
      
          if (!userEmail) {
            return res.status(401).json({ 
              success: false, 
              error: 'User not authenticated'
            });
          }
      
          const db = await connectToDatabase();
          const notificationsCollection = db.collection('notifications');
      
          const result = await notificationsCollection.updateMany(
            { 
              _id: { $in: notificationIds.map(id => new ObjectId(id)) },
              userEmail: userEmail
            },
            { $set: { read: true } }
          );
      
          res.json({
            success: true,
            message: 'Notifications marked as read',
            modifiedCount: result.modifiedCount
          });
        } catch (error) {
          console.error('Error marking notifications as read:', error);
          res.status(500).json({ 
            success: false, 
            error: 'Internal server error'
          });
        }
      });

      async function createNotification(userEmail, type, message, relatedId) {
        const db = await connectToDatabase();
        const notificationsCollection = db.collection('notifications');
        
        const notification = {
          userEmail,
          type,
          message,
          relatedId,
          timestamp: new Date(),
          read: false
        };
      
        await notificationsCollection.insertOne(notification);
      }

      app.post('/api/clearAllNotifications', async (req, res) => {
        try {
          const userEmail = req.session?.user?.email;
      
          if (!userEmail) {
            return res.status(401).json({ 
              success: false, 
              error: 'User not authenticated'
            });
          }
      
          const db = await connectToDatabase();
          const notificationsCollection = db.collection('notifications');
      
          const result = await notificationsCollection.deleteMany({ userEmail: userEmail });
      
          res.json({
            success: true,
            message: 'All notifications cleared',
            deletedCount: result.deletedCount
          });
        } catch (error) {
          console.error('Error clearing notifications:', error);
          res.status(500).json({ 
            success: false, 
            error: 'Internal server error'
          });
        }
      });