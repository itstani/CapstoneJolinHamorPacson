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

app.use(express.json())
app.use(
  session({
    secret: "N3$Pxm/mXm1eYY",
    resave: false,
    saveUninitialized: true,
  }),
)

function getClient() {
  return new MongoClient(uri, {
    serverApi: {
      version: ServerApiVersion.v1,
      strict: true,
      deprecationErrors: true,
    },
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
}
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
  maxPoolSize: 10,
  minPoolSize: 5,
  retryWrites: true,
  retryReads: true,
  w: "majority",
  connectTimeoutMS: 30000,
  socketTimeoutMS: 45000,
})

let database
let activityLogsCollection

app.use((req, res, next) => {
  const allowedOrigins = ["http://localhost:3000", "http://localhost:5500", "http://127.0.0.1:5500","https://avidasetting.onrender.com"]
  const origin = req.headers.origin

  if (allowedOrigins.includes(origin)) {
    res.header("Access-Control-Allow-Origin", origin)
  } else {
    res.header("Access-Control-Allow-Origin", "*")
  }

  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization")
  res.header("Access-Control-Allow-Credentials", "true")

  if (req.method === "OPTIONS") {
    return res.status(204).end()
  }

  next()
})

app.use((req, res, next) => {
  const allowedOrigins = ["http://localhost:3000", "http://localhost:5500", "http://127.0.0.1:5500"]
  const origin = req.headers.origin

  if (allowedOrigins.includes(origin)) {
    res.header("Access-Control-Allow-Origin", origin)
  } else {
    res.header("Access-Control-Allow-Origin", "*")
  }

  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization")
  res.header("Access-Control-Allow-Credentials", "true")

  if (req.method === "OPTIONS") {
    return res.status(204).end()
  }

  next()
})

async function connectToDatabase() {
  try {
    await client.connect()
    console.log("Connected successfully to MongoDB")
    return client.db(dbName)
  } catch (error) {
    console.error("MongoDB connection error:", error)
    throw error
  }
}

 async function connectToDatabase() {
  try {
    if (!global.mongoClient) {
      await client.connect()
      global.mongoClient = client
      console.log("Connected successfully to MongoDB Atlas")
    }
    return client.db(dbName)
  } catch (error) {
    console.error("MongoDB connection error:", error)
    throw error
  }
} 

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))
app.use(express.static(path.join(__dirname)))

// Specific static file handling with logging
app.use("/images", (req, res, next) => {
  const imagePath = path.join(__dirname, "images", req.path)
  console.log("Image request:", {
    path: req.path,
    fullPath: imagePath,
    exists: fs.existsSync(imagePath),
  })

  res.sendFile(imagePath, (err) => {
    if (err) {
      console.error("Error serving image:", err)
      next(err)
    }
  })
})

app.use(
  "/images",
  express.static(path.join(__dirname, "images"), {
    setHeaders: (res) => {
      res.setHeader("Cache-Control", "public, max-age=31536000")
      res.setHeader("Access-Control-Allow-Origin", "*")
    },
  }),
)

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*")
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept")
  next()
})

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

app.get("/debug-images", (req, res) => {
  const imagesPath = path.join(__dirname, "images")
  const fs = require("fs")
  try {
    const files = fs.readdirSync(imagesPath)
    res.json({
      imagesPath,
      files,
      exists: fs.existsSync(imagesPath),
    })
  } catch (error) {
    res.json({
      error: error.message,
      imagesPath,
      exists: false,
    })
  }
})

app.use(
  "/CSS",
  express.static(path.join(__dirname, "CSS"), {
    setHeaders: (res, path) => {
      res.set("Cache-Control", "public, max-age=31536000")
    },
  }),
)

// Add explicit favicon handling
app.get("/favicon.ico", (req, res) => {
  res.sendFile(path.join(__dirname, "images", "favicon.ico"))
})
app.use("/Webpages", express.static(path.join(__dirname, "Webpages")))
app.use(cors())
app.use(session({
  secret: process.env.SESSION_SECRET || "N3$Pxm/mXm1eYY",
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

app.use(cors({
  origin: process.env.NODE_ENV === "production" 
    ? "https://capstone-jolin-hamor-pacson.vercel.app" 
    : "http://localhost:3000",
  credentials: true
}));
app.use(
  session({
    secret: "N3$Pxm/mXm1eYY",
    resave: false,
    saveUninitialized: true,
    cookie: { secure: app.get("env") === "production" },
  }),
)

app.use(
  cors({
    origin:
      process.env.NODE_ENV === "production"
        ? "https://capstone-jolin-hamor-pacson.vercel.app"
        : "http://localhost:3000",
    credentials: true,
  }),
)

// Example route
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "Webpages/login.html"))
})

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "Webpages", "login.html"))
})

app.use(
  session({
    secret: process.env.SESSION_SECRET || "N3$Pxm/mXm1eYY",
    resave: false,
    saveUninitialized: true,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
      maxAge: 24 * 60 * 60 * 1000,
    },
  }),
)

// Middleware to attach the database
app.use(async (req, res, next) => {
  try {
    req.db = await connectToDatabase()
    next()
  } catch (error) {
    next(error)
  }
})

connectToDatabase().catch(console.error)

// Debug middleware to log all requests
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`)
  next()
})

// Health check endpoint
app.get("/health", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() })
})

const uploadsDir = path.join(__dirname, "uploads")
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true })
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/")
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname))
  },
})

const upload = multer({ storage: storage })

app.post("/upload-receipt", upload.single("receipt"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: "No file uploaded",
      })
    }

    // Read the uploaded file
    const filePath = req.file.path
    const fileBuffer = fs.readFileSync(filePath)

    // Convert the file to Base64
    const base64Image = fileBuffer.toString("base64")
    const mimeType = req.file.mimetype

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
      timestamp: new Date(),
    }

    // Save to MongoDB
    const db = await getClient().db(dbName)
    const paymentsCollection = db.collection("eventpayments")
    await paymentsCollection.insertOne(paymentData)

    // Cleanup the temporary file
    fs.unlinkSync(filePath)

    res.status(200).json({
      success: true,
      message: "Receipt uploaded and payment processed successfully!",
    })
  } catch (err) {
    console.error("Error handling receipt upload:", err)
    // Cleanup the temporary file if it exists
    if (req.file && req.file.path) {
      try {
        fs.unlinkSync(req.file.path)
      } catch (unlinkErr) {
        console.error("Error deleting temporary file:", unlinkErr)
      }
    }
    res.status(500).json({
      success: false,
      message: "Error processing payment. Please try again.",
    })
  }
})

app.get("/api/generate-report", async (req, res) => {
  try {
    const db = await connectToDatabase()
    const aeventsCollection = db.collection("aevents")
    const homeownersCollection = db.collection("homeowners")
    const eventpaymentsCollection = db.collection("eventpayments")

    const now = new Date()
    const lastMonth = new Date(now.getFullYear(), now.getMonth() - 1, 1)
    const startOfLastMonth = new Date(lastMonth.getFullYear(), lastMonth.getMonth(), 1)
    const endOfLastMonth = new Date(now.getFullYear(), now.getMonth(), 0)

    // Get all events from last month
    const events = await aeventsCollection
      .find({
        eventDate: {
          $gte: startOfLastMonth.toISOString().split("T")[0],
          $lte: endOfLastMonth.toISOString().split("T")[0],
        },
      })
      .toArray()

    const docx = officegen("docx")

    docx.on("error", (err) => {
      console.log(err)
      res.status(500).send("Error generating document")
    })

    // Add title
    const titleParagraph = docx.createP()
    titleParagraph.addText("Last Month's Reservation Report", {
      bold: true,
      font_size: 18,
    })

    // Process each event
    for (const event of events) {
      try {
        // Find homeowner information
        const homeowner = await homeownersCollection.findOne({
          email: event.userEmail,
        })

        // Find payment information
        const payment = await eventpaymentsCollection.findOne({
          eventName: event.eventName,
          eventDate: event.eventDate,
        })

        // Create a new paragraph for each event
        const eventParagraph = docx.createP()

        // Add homeowner information
        eventParagraph.addText(`Homeowner: ${homeowner ? `${homeowner.firstName} ${homeowner.lastName}` : "N/A"}`, {
          bold: true,
        })
        eventParagraph.addLineBreak()
        eventParagraph.addText(`Address: ${homeowner ? homeowner.address : "N/A"}`)
        eventParagraph.addLineBreak()

        // Add event details
        eventParagraph.addText(`Amenity: ${event.amenity || "N/A"}`)
        eventParagraph.addLineBreak()
        eventParagraph.addText(`Date Reserved: ${event.eventDate || "N/A"}`)
        eventParagraph.addLineBreak()
        eventParagraph.addText(`Event Type: ${event.eventType || "N/A"}`)
        eventParagraph.addLineBreak()
        eventParagraph.addText(`Start Time: ${event.startTime || "N/A"}`)
        eventParagraph.addLineBreak()
        eventParagraph.addText(`End Time: ${event.endTime || "N/A"}`)
        eventParagraph.addLineBreak()

        // Add payment information
        eventParagraph.addText(`Amount Paid: ${payment ? `₱${payment.amount}` : "N/A"}`)
        eventParagraph.addLineBreak()
        eventParagraph.addText(`Payment Status: ${payment ? "Paid" : "Pending"}`)
        eventParagraph.addLineBreak()
        eventParagraph.addLineBreak()
      } catch (eventError) {
        console.error("Error processing event:", eventError)
        // Continue with next event if there's an error with current one
        continue
      }
    }

    const tempFilePath = path.join(__dirname, "temp_report.docx")
    const out = fs.createWriteStream(tempFilePath)

    out.on("error", (err) => {
      console.log(err)
      res.status(500).send("Error saving document")
    })

    out.on("finish", () => {
      const today = new Date().toISOString().split("T")[0]
      res.download(tempFilePath, `${today}-monthlyreport.docx`, (err) => {
        if (err) {
          console.log(err)
          res.status(500).send("Error downloading document")
        }
        fs.unlink(tempFilePath, (unlinkErr) => {
          if (unlinkErr) console.log("Error deleting temporary file:", unlinkErr)
        })
      })
    })

    docx.generate(out)
  } catch (error) {
    console.error("Error generating report:", error)
    res.status(500).json({ error: "Failed to generate report" })
  }
})

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "Webpages/login.html"))
})

/* // Update the login endpoint
app.post("/api/login", async (req, res) => {
  console.log("Login attempt received:", req.body);

  const { login, password } = req.body;

  if (!login || !password) {
    console.log("Missing login or password");
    return res.status(400).json({
      success: false,
      message: "Email/username and password are required"
    });
  }
}) */
// Add CORS middleware
app.use((req, res, next) => {
  res.header(
    "Access-Control-Allow-Origin",
    process.env.NODE_ENV === "production" ? "https://capstone-jolin-hamor-pacson.vercel.app" : "http://localhost:3000",
  )
  res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept")
  res.header("Access-Control-Allow-Credentials", "true")

  // Handle preflight requests
  if (req.method === "OPTIONS") {
    return res.status(200).end()
  }
  next()
})

app.post("/api/login", async (req, res) => {
  const { login, password } = req.body
  const db = await connectToDatabase()

  try {
    console.log("Attempting to connect to database...");
    console.log("Connected to database successfully");

    const usersCollection = db.collection("acc");
    if (!login || !password) {
      return res.status(400).json({
        success: false,
        message: "Email and password are required",
      })
    }

    

    console.log("Searching for user...");
    const user = await usersCollection.findOne({
      $or: [
        { email: { $regex: new RegExp(`^${login}$`, "i") } },
        { username: { $regex: new RegExp(`^${login}$`, "i") } },
      ],
    })

    if (!user) {
      console.log("User not found");
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      })
    }

    console.log("User found, comparing passwords...");
    const isValidPassword = await bcrypt.compare(password, user.password);
    

    console.log("Login successful for user:", user.username);
    // Log successful login
    await logActivity("login", `User ${user.username} logged in successfully`)

    res.json({
      success: true,
      username: user.username,
      email: user.email,
      redirectUrl: user.role === "admin" ? "/Webpages/AdHome.html" : "/Webpages/HoHome.html",
    })
  } catch (error) {
    console.error("Login error:", error)
    res.status(500).json({
      success: false,
      message: "An error occurred during login",
      error: error.message
    });
  }
})


async function logActivity(action, details) {
  try {
    if (!activityLogsCollection) {
      const db = await connectToDatabase()
      activityLogsCollection = db.collection("activityLogs")
    }
    await activityLogsCollection.insertOne({
      action,
      details,
      timestamp: new Date(),
    })
  } catch (error) {
    console.error("Error logging activity:", error)
  }
}

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

    const database = getClient().db(dbName)
    const usersCollection = database.collection("acc")

    // Update user details
    const updateFields = { username: newUsername }

    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10)
      updateFields.password = hashedPassword
    }

    const result = await usersCollection.updateOne({ email: req.session.user.email }, { $set: updateFields })

    if (result.modifiedCount > 0) {
      await logActivity("profileUpdate", `User ${req.session.user.email} updated their profile`) // Log activity
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

// Update the existing addevent endpoint
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

app.post("/delEvent", async (req, res) => {
  const { username } = req.body
  try {
    const db = await connectToDatabase()

    const database = getClient().db(dbName)
    const eventsCollection = database.collection("events")
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
app.get("/eventfin", async (req, res) => {
  try {
    const db = await connectToDatabase()

    const database = getClient().db(dbName)
    const eventsCollection = database.collection("events")
    const events = await eventsCollection.find({}).toArray()
    res.json(events)
  } catch (error) {
    console.error("Error fetching events:", error)
    res.status(500).send("An error occurred while fetching events")
  }
})
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
app.get("/profile", async (req, res) => {
  if (!req.session.user) {
    return res.json({ success: false, message: "Not logged in" })
  }
  const { email } = req.session.user
  try {
    const db = await connectToDatabase()
    const database = getClient().db(dbName)
    const homeownersCollection = database.collection("homeowners")
    const accCollection = database.collection("acc")
    const accUser = await accCollection.findOne({ email })
    const homeownerUser = await homeownersCollection.findOne({ email })

    if (accUser && homeownerUser) {
      return res.json({
        success: true,
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

app.get("/approved-events", async (req, res) => {
  try {
    const db = await connectToDatabase()
    const aeventsCollection = db.collection("aevents")
    const approvedEvents = await aeventsCollection.find().toArray()
    res.json({ success: true, events: approvedEvents })
  } catch (error) {
    console.error("Error fetching approved events:", error)
    res.status(500).json({
      success: false,
      message: "Error fetching approved events",
      events: [],
    })
  }
})

// Add new function to check and delete unpaid events
async function checkAndDeleteUnpaidEvents() {
  try {
    const db = await connectToDatabase()
    const aeventsCollection = db.collection("aevents")
    const eventpaymentsCollection = db.collection("eventpayments")
    const notificationsCollection = db.collection("notifications")

    // Get all approved events
    const approvedEvents = await aeventsCollection.find().toArray()
    const eventPayments = await eventpaymentsCollection.find().toArray()
    const paidEventsMap = new Map(eventPayments.map((payment) => [payment.eventName, true]))

    // Check each event
    for (const event of approvedEvents) {
      if (!paidEventsMap.has(event.eventName)) {
        const eventDate = new Date(event.approvedAt)
        const threeDaysAgo = new Date()
        threeDaysAgo.setDate(threeDaysAgo.getDate() - 3)

        // If event is older than 3 days and unpaid
        if (eventDate < threeDaysAgo) {
          // Delete the event
          await aeventsCollection.deleteOne({ _id: event._id })

          // Create notification for the user
          await createNotification(
            event.userEmail,
            "event_deleted",
            `Your event "${event.eventName}" has been automatically cancelled due to pending payment for more than 3 days.`,
            event._id,
          )

          // Log the activity
          await logActivity(
            "eventAutoCancelled",
            `Event ${event.eventName} was automatically cancelled due to pending payment`,
          )
        }
      }
    }
  } catch (error) {
    console.error("Error in checkAndDeleteUnpaidEvents:", error)
  }
}

// Schedule the check to run daily at midnight
schedule.scheduleJob("0 0 * * *", checkAndDeleteUnpaidEvents)

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



// Add this after your existing createNotification function
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

app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Failed to destroy session:", err)
      return res.status(500).json({ message: "Failed to log out" })
    }
    res.status(200).json({ message: "Logout successful" })
  })
})
async function run() {
  try {
    await connectToDatabase()
    console.log("Pinged your deployment. You successfully connected to MongoDB!")
  } catch (error) {
    console.error("Error connecting to MongoDB:", error)
  }
}
run().catch(console.dir)

//get data from acc collection to display in homeowner table hotable.html
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

app.put("/updateHomeowner/:email", async (req, res) => {
  const { email } = req.params
  const updateData = req.body

  try {
    const db = await connectToDatabase()

    const database = getClient().db("avidadb")
    const collection = database.collection("homeowners")

    // Retrieve the homeowner's document to get the last name
    const homeowner = await collection.findOne({ email: email })

    if (!homeowner) {
      return res.json({ success: false, message: "Homeowner not found" })
    }

    const result = await collection.updateOne({ email: email }, { $set: updateData })

    if (result.modifiedCount > 0) {
      const lastName = homeowner.lastName // Assuming 'lastName' is the field storing the last name
      await logActivity("homeownerUpdate", `Homeowner with Last Name ${lastName} updated`) // Log activity
      res.json({ success: true, message: "Homeowner updated successfully" })
    } else {
      res.json({ success: false, message: "No document matched the query" })
    }
  } catch (error) {
    console.error("Error updating homeowner:", error)
    res.status(500).json({ success: false, error: "Failed to update homeowner" })
  }
})

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

// Update the existing approve event route
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

app.post("/disapprove-event", async (req, res) => {
  const { eventName, reason } = req.body

  try {
    const db = await connectToDatabase()
    const eventpaymentsCollection = db.collection("eventpayments")
    const eventsCollection = db.collection("events")
    const deventsCollection = db.collection("devents") // Disapproved events collection

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
      await logActivity("eventDisapproval", `Event ${eventName} disapproved. Reason: ${reason}`) // Log activity
      res.json({ success: true, message: "Event disapproved and moved to disapproved events." })
    } else {
      res.status(404).json({ success: false, message: "Event not found in events collection." })
    }
  } catch (error) {
    console.error("Error disapproving event:", error)
    res.status(500).json({ success: false, message: "Server error while disapproving event." })
  }
})

app.get("/receipt-image", async (req, res) => {
  const { eventName, eventDate } = req.query

  try {
    const eventpaymentsCollection = req.db.collection("eventpayments")
    const eventsCollection = req.db.collection("events")

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

app.get("/eventshow", async (req, res) => {
  const { eventName, eventDate } = req.query

  try {
    const eventsCollection = req.db.collection("events")

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

//Submit Concern
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
      status: "new", // Add this line
    }

    const db = getClient().db("avidadb")
    await db.collection("Concerns").insertOne(concern)

    res.json({ success: true })
  } catch (error) {
    console.error("Error adding concern:", error)
    res.json({ success: false, message: error.message })
  }
})

//Concern Table
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

process.on("SIGINT", async () => {
  if (global.client) {
    await global.client.close()
    console.log("MongoDB connection closed.")
  }
  process.exit(0)
})

module.exports = app
app.get("/getRecentActivity", async (req, res) => {
  try {
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

app.get("/api/notifications", async (req, res) => {
  try {
    console.log("Session in notifications endpoint:", req.session)

    // Check if the user is authenticated
    if (!req.session || !req.session.user || !req.session.user.email) {
      console.log("User not authenticated in notifications endpoint")
      return res.status(401).json({
        success: false,
        error: "User not authenticated",
        notifications: [],
        unreadCount: 0,
      })
    }

    const userEmail = req.session.user.email
    console.log("Fetching notifications for:", userEmail)

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

    console.log(`Found ${notifications.length} notifications for ${userEmail}`)
    console.log("Notifications:", JSON.stringify(notifications))

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

async function createNotification(userEmail, type, message, relatedId) {
  const db = await connectToDatabase()
  const notificationsCollection = db.collection("notifications")

  const notification = {
    userEmail,
    type,
    message,
    relatedId,
    timestamp: new Date(),
    read: false,
  }

  await notificationsCollection.insertOne(notification)
}

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

// userdata edit

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

//update user profile

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

// CONCERN REPLY-----------------------------------------------
// Handle form submission
app.post("/sendReply", upload.single("attachment"), async (req, res) => {
  const { subject, message, concernId } = req.body // Added concernId
  const attachment = req.file ? req.file.filename : null

  // Validate inputs
  if (!subject || !message || !concernId) {
    // Added validation for concernId
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

async function startServer() {
  try {
    await connectToDatabase()
    app.listen(port, () => {
      console.log(`Server is running on http://localhost:${port}`)
    })
  } catch (error) {
    console.error("Failed to start server:", error)
    process.exit(1)
  }
}

app.options("*", cors())

app.use(express.json())
app.use(express.urlencoded({ extended: true }))

app.use(bodyParser.json())

//generate otp
const generateOTP = () => {
  return Math.floor(1000 + Math.random() * 9000) //4 otp
}

//otp sending
app.post("/send-otp", (req, res) => {
  const userEmail = req.body.email
  const otp = generateOTP()

  // Assuming you have configured transporter (nodemailer) elsewhere
  const mailOptions = {
    from: "test@mail", // Replace with your email address
    to: userEmail,
    subject: "Your OTP Code",
    text: `Your OTP code is: ${otp}`,
  }

  // transporter.sendMail(mailOptions, (error, info) => { ... }); // Uncomment and implement if you have nodemailer setup
  res.json({ success: true, message: "OTP sent successfully", otp }) // Send OTP in response for testing
})

app.listen(port, (err) => {
  if (err) {
    console.error("Failed to start server:", err.message)
    process.exit(1)
  }
  console.log(`Server is running on http://localhost:${port}`)
})

app.use((err, req, res, next) => {
  console.error(err.stack)
  res.status(500).json({
    error: "Internal Server Error",
    message: process.env.NODE_ENV === "development" ? err.message : undefined,
  })
})

app.use((err, req, res, next) => {
  console.error("Unhandled error:", err)
  res.status(500).json({
    error: "Internal server error",
    message: process.env.NODE_ENV === "development" ? err.message : "An unexpected error occurred",
    timestamp: new Date().toISOString(),
  })
})

app.use((req, res) => {
  res.status(404).json({
    error: "Not Found",
    message: `Route ${req.method} ${req.path} not found`,
    timestamp: new Date().toISOString(),
  })
})

module.exports = app

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    success: false,
    message: 'An unexpected error occurred',
    error: process.env.NODE_ENV === 'production' ? 'Internal server error' : err.message
  });
});
app.use((req, res, next) => {
  const oldJson = res.json
  res.json = (data) => {
    console.log("Response data:", JSON.stringify(data))
    oldJson.apply(res, arguments)
  }
  next()
})
