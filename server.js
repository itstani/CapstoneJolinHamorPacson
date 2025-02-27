require("dotenv").config()
const express = require("express")
const bodyParser = require("body-parser")
const multer = require("multer")
const path = require("path")
const session = require("express-session")
const bcrypt = require("bcryptjs")
const cors = require("cors")
const fs = require("fs")
const { ObjectId } = require("mongodb")
const { MongoClient, ServerApiVersion } = require("mongodb")
const schedule = require("node-schedule")
const officegen = require("officegen")

const app = express()
const port = 3000
const dbName = process.env.DB_NAME || "avidadb"
const uri = process.env.MONGODB_URI

// Helper function to get date range for analytics
function getDateRange(filter) {
  const now = new Date()
  switch (filter) {
    case "week":
      return new Date(now.setDate(now.getDate() - 7))
    case "1 month":
      return new Date(now.setMonth(now.getMonth() - 1))
    case "6 months":
      return new Date(now.setMonth(now.getMonth() - 6))
    case "year":
      return new Date(now.setFullYear(now.getFullYear() - 1))
    default:
      return new Date(0) // Beginning of time
  }
}

// MongoDB connection function - optimized for serverless
async function connectToDatabase() {
  const client = new MongoClient(uri, {
    serverApi: {
      version: ServerApiVersion.v1,
      strict: true,
      deprecationErrors: true,
    },
    maxPoolSize: 10,
    minPoolSize: 1,
    retryWrites: true,
    retryReads: true,
    w: "majority",
    connectTimeoutMS: 30000,
    socketTimeoutMS: 45000,
  })

  try {
    if (!uri) {
      throw new Error('MongoDB URI is not defined');
    }
    await client.connect();
    await client.db().command({ ping: 1 }); // Test the connection
    console.log("Successfully connected to MongoDB");
    return client.db(dbName);
  } catch (error) {
    console.error("MongoDB connection error:", error);
    throw new Error(`Database connection failed: ${error.message}`);
  }
}

app.use(express.json())
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

// Configure CORS - single configuration
app.use(
  cors({
    origin:
      process.env.NODE_ENV === "production"
        ? "https://capstone-jolin-hamor-pacson.vercel.app"
        : "http://localhost:3000",
    credentials: true,
  }),
)

// Update session configuration for Vercel serverless environment
app.use(
  session({
    secret: process.env.SESSION_SECRET || "N3$Pxm/mXm1eYY",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
      httpOnly: true,
    },
    name: 'sessionId', // Custom session cookie name
  }),
)

app.use(express.static(path.join(__dirname)))
app.use(
  "/images",
  express.static(path.join(__dirname, "images"), {
    setHeaders: (res) => {
      res.setHeader("Cache-Control", "public, max-age=31536000")
      res.setHeader("Access-Control-Allow-Origin", "*")
    },
  }),
)
app.use(
  "/CSS",
  express.static(path.join(__dirname, "CSS"), {
    setHeaders: (res) => {
      res.set("Cache-Control", "public, max-age=31536000")
    },
  }),
)
app.use("/Webpages", express.static(path.join(__dirname, "Webpages")))

// Configure file uploads for serverless environment
// In serverless, we need to use memory storage instead of disk storage
const memoryStorage = multer.memoryStorage()
const upload = multer({
  storage: memoryStorage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  },
})

// Middleware to attach the database
app.use(async (req, res, next) => {
  try {
    req.db = await connectToDatabase()
    next()
  } catch (error) {
    next(error)
  }
})

// Add session check middleware
app.use((req, res, next) => {
  if (!req.session) {
    console.error("Session middleware not properly initialized");
  }
  next();
});

// Debug middleware to log all requests
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`)
  next()
})

// Health check endpoint
app.get("/health", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() })
})

// Debug endpoint
app.get("/debug", async (req, res) => {
  try {
    // Collect environment information
    const envInfo = {
      nodeEnv: process.env.NODE_ENV,
      mongodbUri: process.env.MONGODB_URI ? "Set" : "Not set",
      dbName: process.env.DB_NAME,
      vercelEnv: process.env.VERCEL_ENV,
      region: process.env.VERCEL_REGION,
    }

    // Test database connection
    let dbConnection = "Not tested"
    let collections = []
    try {
      const db = await connectToDatabase()
      collections = await db.listCollections().toArray()
      dbConnection = "Success"
    } catch (dbError) {
      dbConnection = `Error: ${dbError.message}`
    }

    // Collect request information
    const requestInfo = {
      headers: req.headers,
      cookies: req.cookies,
      query: req.query,
      method: req.method,
      path: req.path,
      protocol: req.protocol,
      hostname: req.hostname,
    }

    res.json({
      timestamp: new Date().toISOString(),
      status: "debug_endpoint_working",
      environment: envInfo,
      database: {
        connection: dbConnection,
        collections: collections.map((c) => c.name),
      },
      request: requestInfo,
      serverInfo: {
        platform: process.platform,
        nodeVersion: process.version,
        memoryUsage: process.memoryUsage(),
      },
    })
  } catch (error) {
    console.error("Debug endpoint error:", error)
    res.status(500).json({
      error: "Debug endpoint error",
      message: error.message,
      stack: process.env.NODE_ENV === "development" ? error.stack : undefined,
    })
  }
})

// Database test endpoint
app.get("/api/test-db", async (req, res) => {
  try {
    const db = await connectToDatabase()
    const collections = await db.listCollections().toArray()
    res.json({
      success: true,
      message: "Database connected successfully",
      collections: collections.map((c) => c.name),
    })
  } catch (error) {
    console.error("Database test error:", error)
    res.status(500).json({
      success: false,
      message: "Database connection failed",
      error: error.message,
    })
  }
})

// Login endpoint
app.post("/api/login", async (req, res) => {
  console.log("Login attempt received:", {
    hasLogin: !!req.body.login,
    hasPassword: !!req.body.password,
  });

  const { login, password } = req.body;

  if (!login || !password) {
    return res.status(400).json({
      success: false,
      message: "Email/username and password are required"
    });
  }

  let db;
  try {
    db = await connectToDatabase();
    console.log("Database connected successfully for login");
  } catch (error) {
    console.error("Database connection error during login:", error);
    return res.status(500).json({
      success: false,
      message: "Database connection failed",
      error: process.env.NODE_ENV === "development" ? error.message : "Internal server error"
    });
  }

  try {
    const usersCollection = db.collection("acc");
    console.log("Searching for user with login:", login);

    const user = await usersCollection.findOne({
      $or: [
        { email: { $regex: new RegExp(`^${login}$`, "i") } },
        { username: { $regex: new RegExp(`^${login}$`, "i") } }
      ]
    });

    if (!user) {
      console.log("User not found for login:", login);
      return res.status(401).json({
        success: false,
        message: "Invalid credentials"
      });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    
    if (!isValidPassword) {
      console.log("Invalid password for user:", login);
      return res.status(401).json({
        success: false,
        message: "Invalid credentials"
      });
    }

    // Set session data
    req.session.user = {
      id: user._id,
      username: user.username,
      email: user.email,
      role: user.role
    };

    // Save session explicitly
    req.session.save((err) => {
      if (err) {
        console.error("Session save error:", err);
        return res.status(500).json({
          success: false,
          message: "Failed to create session"
        });
      }

      console.log("Login successful for user:", user.username);
      res.json({
        success: true,
        username: user.username,
        email: user.email,
        redirectUrl: user.role === "admin" ? "/Webpages/AdHome.html" : "/Webpages/HoHome.html"
      });
    });

  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      success: false,
      message: "An error occurred during login",
      error: process.env.NODE_ENV === "development" ? error.message : "Internal server error"
    });
  }
})

// Activity logging function
async function logActivity(action, details) {
  try {
    const db = await connectToDatabase()
    const activityLogsCollection = db.collection("activityLogs")
    await activityLogsCollection.insertOne({
      action,
      details,
      timestamp: new Date(),
    })
  } catch (error) {
    console.error("Error logging activity:", error)
  }
}

// Notification creation function
async function createNotification(userEmail, type, message, relatedId) {
  try {
    const db = await connectToDatabase()
    const notificationsCollection = db.collection("notifications")

    await notificationsCollection.insertOne({
      userEmail,
      type,
      message,
      relatedId,
      timestamp: new Date(),
      read: false,
    })
  } catch (error) {
    console.error("Error creating notification:", error)
  }
}

// Check user existence endpoint
app.get("/check-existence", async (req, res) => {
  const { field, value } = req.query

  try {
    const db = await connectToDatabase()
    const usersCollection = db.collection("acc")

    const query = { [field]: value }
    const existingUser = await usersCollection.findOne(query)

    res.json({ exists: !!existingUser })
  } catch (error) {
    console.error("Error checking existence:", error)
    res.status(500).json({ error: "An error occurred" })
  }
})

// Registration endpoint
app.post("/register", async (req, res) => {
  const { username, email, password, isHomeowner } = req.body
  if (!username || !email || !password) {
    return res.json({ message: "Missing required fields", success: false })
  }
  try {
    const db = await connectToDatabase()
    const usersCollection = db.collection("acc")

    const existingUser = await usersCollection.findOne({ $or: [{ username }, { email }] })
    if (existingUser) {
      return res.json({
        message: "Username or email already exists. Please choose different ones.",
        success: false,
      })
    }

    const hashedPassword = await bcrypt.hash(password, 10)
    const newUser = {
      username,
      email,
      password: hashedPassword,
      isHomeowner,
    }

    await usersCollection.insertOne(newUser)

    res.json({ message: "Registration successful", success: true })
  } catch (error) {
    console.error("Error during registration:", error)
    res.json({ message: "An error occurred", success: false })
  }
})

// Homeowner details endpoint
app.post("/homeowner-details", async (req, res) => {
  const { email, firstName, lastName, address, phoneNumber, landline } = req.body
  if (!email || !firstName || !lastName || !address || !phoneNumber) {
    return res.json({ message: "Missing required fields", success: false })
  }
  try {
    const db = await connectToDatabase()
    const homeownersCollection = db.collection("homeowners")

    const newHomeowner = {
      email,
      firstName,
      lastName,
      address,
      phoneNumber,
      landline,
      paymentStatus: "To be verified",
      homeownerStatus: "To be verified",
    }

    await homeownersCollection.insertOne(newHomeowner)

    res.json({ message: "Homeowner details added successfully", success: true })
  } catch (error) {
    console.error("Error adding homeowner details:", error)
    res.json({ message: "An error occurred", success: false })
  }
})

// Update profile endpoint
app.post("/updateProfile", async (req, res) => {
  const { newUsername, password } = req.body

  if (!req.session.user) {
    return res.json({
      success: false,
      message: "You must be logged in to update your profile.",
    })
  }

  if (!newUsername || newUsername.trim() === "") {
    return res.json({ success: false, message: "Username cannot be empty." })
  }

  try {
    const db = await connectToDatabase()
    const usersCollection = db.collection("acc")

    // Update user details
    const updateFields = { username: newUsername }

    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10)
      updateFields.password = hashedPassword
    }

    const result = await usersCollection.updateOne({ email: req.session.user.email }, { $set: updateFields })

    if (result.modifiedCount > 0) {
      await logActivity("profileUpdate", `User ${req.session.user.email} updated their profile`)
      res.json({ success: true, message: "Profile updated successfully." })
    } else {
      res.json({ success: false, message: "No changes made to the profile." })
    }
  } catch (error) {
    console.error("Error updating profile:", error)
    res.json({
      success: false,
      message: "An error occurred while updating profile.",
    })
  }
})

// Get user info endpoint
app.get("/api/user-info", (req, res) => {
  if (!req.session || !req.session.user || !req.session.user.email) {
    return res.status(401).json({
      success: false,
      message: "User not authenticated",
    })
  }

  res.json({
    success: true,
    email: req.session.user.email,
  })
})

// Add event endpoint
app.post("/addevent", async (req, res) => {
  if (!req.session || !req.session.user || !req.session.user.email) {
    return res.status(401).json({
      success: false,
      message: "User not authenticated",
    })
  }

  const { HomeownerName, eventName, eventDate, startTime, endTime, amenity, eventType, guests, homeownerStatus } =
    req.body
  const userEmail = req.session.user.email // Get email from session

  try {
    const db = await connectToDatabase()
    const eventsCollection = db.collection("events")

    // Add event to database with user's email
    const newEvent = {
      HomeownerName,
      userEmail, // Include the user's email
      eventName,
      eventDate,
      startTime,
      endTime,
      amenity,
      eventType,
      guests: {
        number: guests.number, // Store number of guests
        names: guests.names, // Store guest names as an array
      },
      homeownerStatus,
      createdAt: new Date(),
    }

    await eventsCollection.insertOne(newEvent)

    res.status(201).json({
      success: true,
      message: "Event created successfully.",
    })
  } catch (error) {
    console.error("Error creating event:", error)
    res.status(500).json({
      success: false,
      message: "An error occurred while creating the event.",
    })
  }
})

// Delete event endpoint
app.post("/delEvent", async (req, res) => {
  const { username } = req.body
  try {
    const db = await connectToDatabase()
    const eventsCollection = db.collection("events")

    const result = await eventsCollection.findOneAndDelete(
      { "createdBy.username": username },
      { sort: { createdAt: -1 } },
    )

    if (result.value) {
      res.json({
        success: true,
        message: "Most recent event deleted successfully.",
      })
    } else {
      res.json({ success: false, message: "Cancelled" })
    }
  } catch (error) {
    console.error("Error deleting recent event:", error)
    res.status(500).json({ success: false, message: "Error deleting recent event." })
  }
})

// Get events endpoint
app.get("/eventfin", async (req, res) => {
  try {
    const db = await connectToDatabase()
    const eventsCollection = db.collection("events")

    const events = await eventsCollection.find({}).toArray()
    res.json(events)
  } catch (error) {
    console.error("Error fetching events:", error)
    res.status(500).send("An error occurred while fetching events")
  }
})

// GCash payment endpoint
app.post("/gcash-payment", async (req, res) => {
  const { amount, eventName, eventDate } = req.body
  try {
    res.json({
      success: true,
      message: "Payment processed successfully with GCash",
    })
  } catch (error) {
    console.error("Error during GCash payment simulation:", error)
    res.json({ success: false, message: "Payment failed. Please try again." })
  }
})

// Get profile endpoint
app.get("/profile", async (req, res) => {
  if (!req.session.user) {
    return res.json({ success: false, message: "Not logged in" })
  }

  const { email } = req.session.user

  try {
    const db = await connectToDatabase()
    const homeownersCollection = db.collection("homeowners")
    const accCollection = db.collection("acc")

    const accUser = await accCollection.findOne({ email })
    const homeownerUser = await homeownersCollection.findOne({ email })

    if (accUser && homeownerUser) {
      return res.json({
        success: true,
        username: req.session.user.username,
        email: req.session.user.email,
        firstname: homeownerUser.firstName,
        lastname: homeownerUser.lastName,
        status: homeownerUser.paymentStatus,
      })
    } else {
      return res.json({ success: false, message: "User not found in one or both collections" })
    }
  } catch (error) {
    console.error("Error fetching user profile:", error)
    return res.status(500).json({ success: false, message: "Server error" })
  }
})

// Get approved events endpoint
app.get("/approved-events", async (req, res) => {
  try {
    const db = await connectToDatabase()
    const aeventsCollection = db.collection("aevents")
    const eventpaymentsCollection = db.collection("eventpayments")

    const approvedEvents = await aeventsCollection.find().toArray()
    const eventPayments = await eventpaymentsCollection.find().toArray()

    // Create a map of paid events for faster lookup
    const paidEventsMap = new Map(eventPayments.map((payment) => [payment.eventName, true]))

    // Add payment status to each event
    const eventsWithPaymentStatus = approvedEvents.map((event) => ({
      ...event,
      isPaid: paidEventsMap.has(event.eventName),
    }))

    res.json({ success: true, events: eventsWithPaymentStatus })
  } catch (error) {
    console.error("Error fetching approved events:", error)
    res.status(500).json({
      success: false,
      message: "Error fetching approved events",
    })
  }
})

// Upload receipt endpoint - modified for serverless
app.post("/upload-receipt", upload.single("receipt"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: "No file uploaded",
      })
    }

    // Get the file buffer from memory storage
    const fileBuffer = req.file.buffer

    // Convert the file to Base64
    const base64Image = fileBuffer.toString("base64")
    const mimeType = req.file.mimetype

    // Construct the MongoDB document
    const paymentData = {
      userEmail: req.body.userEmail,
      eventName: req.body.eventName,
      eventDate: req.body.eventDate,
      amount: req.body.finalAmount,
      startTime: req.body.startTime,
      endTime: req.body.endTime,
      paymentMethod: req.body.paymentMethod,
      receiptImage: `data:${mimeType};base64,${base64Image}`,
      timestamp: new Date(),
    }

    // Save to MongoDB
    const db = await connectToDatabase()
    const paymentsCollection = db.collection("eventpayments")
    await paymentsCollection.insertOne(paymentData)

    res.status(200).json({
      success: true,
      message: "Receipt uploaded and payment processed successfully!",
    })
  } catch (err) {
    console.error("Error handling receipt upload:", err)
    res.status(500).json({
      success: false,
      message: "Error processing payment. Please try again.",
    })
  }
})

// Update payment status endpoint
app.post("/update-payment-status", async (req, res) => {
  try {
    const { eventName, isPaid } = req.body
    const db = await connectToDatabase()
    const eventpaymentsCollection = db.collection("eventpayments")
    const aeventsCollection = db.collection("aevents")

    // Find the event first
    const event = await aeventsCollection.findOne({ eventName })

    if (!event) {
      return res.status(404).json({
        success: false,
        message: "Event not found",
      })
    }

    if (isPaid) {
      // Add to eventpayments collection
      await eventpaymentsCollection.insertOne({
        eventName,
        paidAt: new Date(),
        eventId: event._id,
        userEmail: event.userEmail,
      })

      // Create notification for payment confirmation
      await createNotification(
        event.userEmail,
        "payment_confirmed",
        `Payment confirmed for your event "${eventName}"`,
        event._id,
      )
    } else {
      // Remove from eventpayments collection
      await eventpaymentsCollection.deleteOne({ eventName })
    }

    await logActivity(isPaid ? "paymentConfirmed" : "paymentRemoved", `Payment status updated for event ${eventName}`)

    res.json({
      success: true,
      message: "Payment status updated successfully",
    })
  } catch (error) {
    console.error("Error updating payment status:", error)
    res.status(500).json({
      success: false,
      message: "Error updating payment status",
    })
  }
})

// Logout endpoint
app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Failed to destroy session:", err)
      return res.status(500).json({ message: "Failed to log out" })
    }
    res.status(200).json({ message: "Logout successful" })
  })
})

// Get homeowners endpoint
app.get("/getHomeowners", async (req, res) => {
  try {
    const db = await connectToDatabase()
    const collection = db.collection("homeowners")
    const homeowners = await collection.find().toArray()
    res.json(homeowners)
  } catch (error) {
    console.error("Error fetching data:", error)
    res.status(500).json({ error: "Failed to fetch data" })
  }
})

// Update homeowner endpoint
app.put("/updateHomeowner/:email", async (req, res) => {
  const { email } = req.params
  const updateData = req.body

  try {
    const db = await connectToDatabase()
    const collection = db.collection("homeowners")

    // Retrieve the homeowner's document to get the last name
    const homeowner = await collection.findOne({ email: email })

    if (!homeowner) {
      return res.json({ success: false, message: "Homeowner not found" })
    }

    const result = await collection.updateOne({ email: email }, { $set: updateData })

    if (result.modifiedCount > 0) {
      const lastName = homeowner.lastName
      await logActivity("homeownerUpdate", `Homeowner with Last Name ${lastName} updated`)
      res.json({ success: true, message: "Homeowner updated successfully" })
    } else {
      res.json({ success: false, message: "No document matched the query" })
    }
  } catch (error) {
    console.error("Error updating homeowner:", error)
    res.status(500).json({ success: false, error: "Failed to update homeowner" })
  }
})

// Get pending events endpoint
app.get("/pending-events", async (req, res) => {
  try {
    const db = await connectToDatabase()
    const eventsCollection = db.collection("events")
    const pendingEvents = await eventsCollection.find({ status: "pending" }).toArray()
    res.json({ success: true, events: pendingEvents })
  } catch (error) {
    console.error("Error fetching pending events:", error)
    res.status(500).json({ success: false, message: "Error fetching events" })
  }
})

// Approve event endpoint
app.put("/approveEvent/:eventName", async (req, res) => {
  const { eventName } = req.params

  try {
    const db = await connectToDatabase()
    const eventsCollection = db.collection("events")
    const aeventsCollection = db.collection("aevents")

    const event = await eventsCollection.findOne({ eventName })

    if (event) {
      const approvedAt = new Date()
      const approvedEvent = await aeventsCollection.insertOne({ ...event, status: "approved", approvedAt })
      await eventsCollection.deleteOne({ eventName })

      // Create a notification for the event approval
      await createNotification(
        event.userEmail,
        "event",
        `Your event "${event.eventName}" has been approved. Please proceed with the payment.`,
        approvedEvent.insertedId,
      )

      res.json({ success: true, message: "Event approved. User notified for payment." })
    } else {
      res.status(404).json({ success: false, message: "Event not found." })
    }
  } catch (error) {
    console.error("Error approving event:", error)
    res.status(500).json({ success: false, message: "Server error while approving event." })
  }
})

// Disapprove event endpoint
app.post("/disapprove-event", async (req, res) => {
  const { eventName, reason } = req.body

  try {
    const db = await connectToDatabase()
    const eventpaymentsCollection = db.collection("eventpayments")
    const eventsCollection = db.collection("events")
    const deventsCollection = db.collection("devents")

    // Fetch event from the events collection
    const event = await eventsCollection.findOne({ eventName })

    if (event) {
      // Move event to devents collection
      await deventsCollection.insertOne({ ...event, disapprovalReason: reason })

      // Remove from events collection
      await eventsCollection.deleteOne({ eventName })

      // Update status to 'disapproved' in eventpayments collection with reason
      await eventpaymentsCollection.updateOne(
        { eventName },
        { $set: { status: "disapproved", disapprovalReason: reason } },
      )
      await logActivity("eventDisapproval", `Event ${eventName} disapproved. Reason: ${reason}`)
      res.json({ success: true, message: "Event disapproved and moved to disapproved events." })
    } else {
      res.status(404).json({ success: false, message: "Event not found in events collection." })
    }
  } catch (error) {
    console.error("Error disapproving event:", error)
    res.status(500).json({ success: false, message: "Server error while disapproving event." })
  }
})

// Get receipt image endpoint
app.get("/receipt-image", async (req, res) => {
  const { eventName, eventDate } = req.query

  try {
    const db = await connectToDatabase()
    const eventpaymentsCollection = db.collection("eventpayments")
    const eventsCollection = db.collection("events")

    // Fetch from `eventpayments` collection
    const paymentEvent = await eventpaymentsCollection.findOne({ eventName, eventDate })

    // Fetch from `events` collection
    const eventDetails = await eventsCollection.findOne({ eventName, eventDate })

    if (paymentEvent) {
      // Combine startTime and endTime if they exist
      const combinedTime =
        eventDetails?.startTime && eventDetails?.endTime ? `${eventDetails.startTime} - ${eventDetails.endTime}` : null

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
      })
    } else {
      res.json({
        success: false,
        message: "Receipt image or event details not found",
      })
    }
  } catch (error) {
    console.error("Error fetching receipt image or event details:", error)
    res.status(500).json({ success: false, message: "Server error" })
  }
})

// Get event details endpoint
app.get("/eventshow", async (req, res) => {
  const { eventName, eventDate } = req.query

  try {
    const db = await connectToDatabase()
    const eventsCollection = db.collection("events")

    // Fetch from `events` collection
    const eventDetails = await eventsCollection.findOne({ eventName, eventDate })

    if (eventDetails) {
      res.json({ success: true, eventDetails })
    } else {
      res.json({ success: false, message: "Event not found" })
    }
  } catch (error) {
    console.error("Error fetching event details:", error)
    res.status(500).json({ success: false, message: "Server error" })
  }
})

// Add concern endpoint
app.post("/addconcern", async (req, res) => {
  const { username, email, subject, message } = req.body

  try {
    const createdAt = new Date()

    const concern = {
      username,
      email,
      subject,
      message,
      createdAt,
      status: "new",
    }

    const db = await connectToDatabase()
    await db.collection("Concerns").insertOne(concern)

    res.json({ success: true })
  } catch (error) {
    console.error("Error adding concern:", error)
    res.json({ success: false, message: error.message })
  }
})

// Get concerns endpoint
app.get("/getConcerns", async (req, res) => {
  try {
    const db = await connectToDatabase()
    const collection = db.collection("Concerns")
    const page = Number.parseInt(req.query.page) || 1
    const limit = 5
    const skip = (page - 1) * limit

    const totalConcerns = await collection.countDocuments()
    const concerns = await collection.find().sort({ createdAt: -1 }).skip(skip).limit(limit).toArray()

    res.json({
      concerns,
      currentPage: page,
      totalPages: Math.ceil(totalConcerns / limit),
    })
  } catch (error) {
    console.error("Error fetching concerns:", error)
    res.status(500).json({ error: "Failed to fetch concerns" })
  }
})

// Get recent activity endpoint
app.get("/getRecentActivity", async (req, res) => {
  try {
    const db = await connectToDatabase()
    const activityLogsCollection = db.collection("activityLogs")
    const page = Number.parseInt(req.query.page) || 1
    const limit = 5
    const skip = (page - 1) * limit

    const totalActivities = await activityLogsCollection.countDocuments()
    const recentActivity = await activityLogsCollection
      .find({})
      .sort({ timestamp: -1 })
      .skip(skip)
      .limit(limit)
      .toArray()

    res.json({
      activities: recentActivity,
      totalPages: Math.ceil(totalActivities / limit),
      currentPage: page,
    })
  } catch (error) {
    console.error("Error fetching recent activity:", error)
    res.status(500).json({ error: "Failed to fetch recent activity" })
  }
})

// Get upcoming events endpoint
app.get("/getUpcomingEvents", async (req, res) => {
  try {
    const db = await connectToDatabase()
    const eventsCollection = db.collection("aevents")

    const page = Number.parseInt(req.query.page) || 1
    const limit = 5
    const skip = (page - 1) * limit

    // Get the current date
    const currentDate = new Date()

    // Find events that are upcoming (event date is greater than or equal to the current date)
    const totalEvents = await eventsCollection.countDocuments({
      eventDate: { $gte: currentDate.toISOString().split("T")[0] },
    })

    const upcomingEvents = await eventsCollection
      .find({
        eventDate: { $gte: currentDate.toISOString().split("T")[0] },
      })
      .sort({ eventDate: 1 })
      .skip(skip)
      .limit(limit)
      .toArray()

    res.json({
      events: upcomingEvents,
      currentPage: page,
      totalPages: Math.ceil(totalEvents / limit),
    })
  } catch (error) {
    console.error("Error fetching upcoming events:", error)
    res.status(500).json({ error: "Failed to fetch upcoming events" })
  }
})

// Get currently reserved amenities endpoint
app.get("/getCurrentlyReservedAmenities", async (req, res) => {
  try {
    const db = await connectToDatabase()
    const reservationsCollection = db.collection("aevents")

    // Get the current date in YYYY-MM-DD format
    const currentDate = new Date().toISOString().split("T")[0]

    // Find reservations for today
    const reservations = await reservationsCollection
      .find({
        eventDate: currentDate,
        status: "approved",
      })
      .toArray()

    console.log("Reservations found:", reservations) // Debug log

    // Extract unique amenities from today's reservations
    const uniqueAmenities = [...new Set(reservations.map((r) => r.amenity))]

    // Create an array of amenity objects with image paths
    const amenities = uniqueAmenities.map((amenity) => ({
      name: amenity,
      imagePath: getAmenityImagePath(amenity),
    }))

    console.log("Amenities to be sent:", amenities) // Debug log

    res.json(amenities)
  } catch (error) {
    console.error("Error fetching currently reserved amenities:", error)
    res.status(500).json({ error: "Failed to fetch currently reserved amenities" })
  }
})

// Helper function to get the image path for each amenity
function getAmenityImagePath(amenityName) {
  switch (amenityName.toLowerCase()) {
    case "clubhouse":
      return "images/clubhouseimg.jpg"
    case "court":
      return "images/Courtimg.jpg"
    case "pool":
      return "images/poolimg.png"
    default:
      return "images/placeholder.jpg"
  }
}

// Resolve concern endpoint
app.post("/resolveConcern/:id", async (req, res) => {
  try {
    const { id } = req.params
    const db = await connectToDatabase()
    const concernsCollection = db.collection("Concerns")

    const result = await concernsCollection.deleteOne({ _id: new ObjectId(id) })

    if (result.deletedCount === 1) {
      await logActivity("concernResolved", `Concern with ID ${id} resolved and deleted`)
      res.json({ success: true, message: "Concern resolved successfully" })
    } else {
      res.json({ success: false, message: "Concern not found" })
    }
  } catch (error) {
    console.error("Error resolving concern:", error)
    res.status(500).json({ success: false, message: "Server error" })
  }
})

// Update concern status endpoint
app.put("/updateConcernStatus/:id", async (req, res) => {
  const { id } = req.params
  const { status } = req.body

  try {
    const db = await connectToDatabase()
    const concernsCollection = db.collection("Concerns")

    const updatedAt = new Date()
    const result = await concernsCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: { status: status, updatedAt } },
    )

    if (result.modifiedCount === 1) {
      await logActivity("concernStatusUpdate", `Concern status updated to ${status}`)

      // Fetch the updated concern to get the user's email
      const updatedConcern = await concernsCollection.findOne({ _id: new ObjectId(id) })

      // Create a notification for the concern status update
      if (updatedConcern) {
        await createNotification(
          updatedConcern.email,
          "concern",
          `Your concern "${updatedConcern.subject}" has been ${status}.`,
          updatedConcern._id,
        )
      }

      res.json({ success: true, message: "Concern status updated successfully" })
    } else {
      res.json({ success: false, message: "Concern not found or status not changed" })
    }
  } catch (error) {
    console.error("Error updating concern status:", error)
    res.status(500).json({ success: false, message: "Server error" })
  }
})

// Get event by ID endpoint
app.get("/api/event/:eventId", async (req, res) => {
  const { eventId } = req.params

  try {
    const db = await connectToDatabase()
    const aeventsCollection = db.collection("aevents")

    const event = await aeventsCollection.findOne({ _id: new ObjectId(eventId) })

    if (event) {
      res.json({ success: true, event })
    } else {
      res.status(404).json({ success: false, message: "Event not found" })
    }
  } catch (error) {
    console.error("Error fetching event details:", error)
    res.status(500).json({ success: false, message: "Server error while fetching event details" })
  }
})

// Get notifications endpoint
app.get("/api/notifications", async (req, res) => {
  try {
    if (!req.session.user || !req.session.user.email) {
      return res.status(401).json({
        success: false,
        error: "User not authenticated",
        notifications: [],
        unreadCount: 0,
      })
    }

    const userEmail = req.session.user.email
    const db = await connectToDatabase()
    const notificationsCollection = db.collection("notifications")

    const notifications = await notificationsCollection
      .find({
        userEmail: userEmail,
        read: false,
      })
      .sort({ timestamp: -1 })
      .limit(10)
      .toArray()

    res.json({
      success: true,
      notifications: notifications,
      unreadCount: notifications.length,
    })
  } catch (error) {
    console.error("Error fetching notifications:", error)
    res.status(500).json({
      success: false,
      error: "Internal server error",
      notifications: [],
      unreadCount: 0,
    })
  }
})

// Mark notifications as read endpoint
app.post("/api/markNotificationsAsRead", async (req, res) => {
  try {
    const userEmail = req.session?.user?.email
    const { notificationIds } = req.body

    if (!userEmail) {
      return res.status(401).json({
        success: false,
        error: "User not authenticated",
      })
    }

    const db = await connectToDatabase()
    const notificationsCollection = db.collection("notifications")

    const result = await notificationsCollection.updateMany(
      {
        _id: { $in: notificationIds.map((id) => new ObjectId(id)) },
        userEmail: userEmail,
      },
      { $set: { read: true } },
    )

    res.json({
      success: true,
      message: "Notifications marked as read",
      modifiedCount: result.modifiedCount,
    })
  } catch (error) {
    console.error("Error marking notifications as read:", error)
    res.status(500).json({
      success: false,
      error: "Internal server error",
    })
  }
})

// Clear all notifications endpoint
app.post("/api/clearAllNotifications", async (req, res) => {
  try {
    const userEmail = req.session?.user?.email

    if (!userEmail) {
      return res.status(401).json({
        success: false,
        error: "User not authenticated",
      })
    }

    const db = await connectToDatabase()
    const notificationsCollection = db.collection("notifications")

    const result = await notificationsCollection.deleteMany({ userEmail: userEmail })

    res.json({
      success: true,
      message: "All notifications cleared",
      deletedCount: result.deletedCount,
    })
  } catch (error) {
    console.error("Error clearing notifications:", error)
    res.status(500).json({
      success: false,
      error: "Internal server error",
    })
  }
})

// Get user details endpoint
app.get("/getUserDetails", async (req, res) => {
  const email = req.query.email

  if (!email) {
    return res.status(400).json({ success: false, message: "Email is required" })
  }

  try {
    const db = await connectToDatabase()
    const collection = db.collection("acc")
    const user = await collection.findOne({ email })

    if (user) {
      res.json({
        success: true,
        username: user.username,
        lastname: user.lastname,
        email: user.email,
        address: user.address || "", //default if no val
        phone: user.phone || "",
        landline: user.landline || "",
      })
    } else {
      res.status(404).json({ success: false, message: "User not found" })
    }
  } catch (error) {
    console.error("Error fetching data:", error)
    res.status(500).json({ success: false, message: "Error fetching user details" })
  }
})

// Update user details endpoint
app.post("/updateUserDetails", async (req, res) => {
  const { email, username, lastname, address, phone, landline, newPassword } = req.body

  try {
    const db = await connectToDatabase()
    const usersCollection = db.collection("acc")

    const updateData = {
      username,
      lastname,
      address,
      phone,
      landline,
    }

    //update pass pag may naka iunput
    if (newPassword) {
      const hashedPassword = await bcrypt.hash(newPassword, 10)
      updateData.password = hashedPassword
    }
    const result = await usersCollection.updateOne({ email }, { $set: updateData })

    if (result.modifiedCount > 0) {
      res.json({ success: true })
    } else {
      res.json({ success: false, message: "User not found or no changes made" })
    }
  } catch (error) {
    console.error("Error updating user details:", error)
    res.status(500).json({ success: false, message: "Internal server error" })
  }
})

// Send reply endpoint
app.post("/sendReply", upload.single("attachment"), async (req, res) => {
  const { subject, message, concernId } = req.body
  const attachment = req.file ? req.file.buffer.toString("base64") : null

  // Validate inputs
  if (!subject || !message || !concernId) {
    return res.status(400).json({ success: false, message: "Subject, message, and concernId are required" })
  }

  try {
    const db = await connectToDatabase()
    const concernsCollection = db.collection("Concerns")

    // Update the concern document with the reply
    await concernsCollection.updateOne(
      { _id: new ObjectId(concernId) },
      {
        $push: { replies: { reply: message, attachment, timestamp: new Date() } },
        $set: { status: "replied" }, // Set status to 'replied'
      },
    )

    // Log the reply activity
    await logActivity("replySent", `Reply to concern: ${subject}`)

    // Send a success response
    res.json({ success: true })
  } catch (error) {
    console.error("Error saving reply:", error)
    res.status(500).json({ success: false, message: "Failed to save reply" })
  }
})

// Analytics: Amenity Reservation Frequency
app.get("/api/analytics/amenity-frequency", async (req, res) => {
  try {
    const db = await connectToDatabase()
    const aeventsCollection = db.collection("aevents")
    const dateFilter = getDateRange(req.query.filter)

    const result = await aeventsCollection
      .aggregate([
        { $match: { eventDate: { $gte: dateFilter.toISOString().split("T")[0] } } },
        { $group: { _id: "$amenity", count: { $sum: 1 } } },
        { $sort: { count: -1 } },
      ])
      .toArray()

    res.json(result)
  } catch (error) {
    console.error("Error fetching amenity frequency:", error)
    res.status(500).json({ error: "Failed to fetch amenity frequency" })
  }
})

// Analytics: Popular Reservation Days
app.get("/api/analytics/popular-days", async (req, res) => {
  try {
    const db = await connectToDatabase()
    const aeventsCollection = db.collection("aevents")
    const dateFilter = getDateRange(req.query.filter)

    const result = await aeventsCollection
      .aggregate([
        { $match: { eventDate: { $gte: dateFilter.toISOString().split("T")[0] } } },
        { $group: { _id: { $dayOfWeek: { $toDate: "$eventDate" } }, count: { $sum: 1 } } },
        { $sort: { count: -1 } },
      ])
      .toArray()

    res.json(result)
  } catch (error) {
    console.error("Error fetching popular reservation days:", error)
    res.status(500).json({ error: "Failed to fetch popular reservation days" })
  }
})

// Analytics: Frequent Event Types
app.get("/api/analytics/event-types", async (req, res) => {
  try {
    const db = await connectToDatabase()
    const aeventsCollection = db.collection("aevents")
    const dateFilter = getDateRange(req.query.filter)

    const result = await aeventsCollection
      .aggregate([
        { $match: { eventDate: { $gte: dateFilter.toISOString().split("T")[0] } } },
        { $group: { _id: "$eventType", count: { $sum: 1 } } },
        { $sort: { count: -1 } },
      ])
      .toArray()

    res.json(result)
  } catch (error) {
    console.error("Error fetching event types:", error)
    res.status(500).json({ error: "Failed to fetch event types" })
  }
})

// Generate OTP function
const generateOTP = () => {
  return Math.floor(1000 + Math.random() * 9000) // 4-digit OTP
