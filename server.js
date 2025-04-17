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
const port = process.env.PORT || 3000
const dbName = process.env.DB_NAME || "avidadb"
const uri = process.env.MONGODB_URI

// === Middleware Configuration (place this after initial requires) ===
// 1. Basic middleware
app.use(express.json())
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

// Add this middleware BEFORE the authentication middleware to ensure it runs first
// Place this right after the app.use(bodyParser.urlencoded({ extended: true })) line

// Special middleware to allow access to MDPayment.html for delinquent users
app.use((req, res, next) => {
  // List of paths that should be accessible even for delinquent users
  const publicPaths = [
    "/login.html",
    "/MDPayment.html",
    "/api/monthly-dues-payment",
    "/api/submit-monthly-payment",
    "/images/",
    "/CSS/",
  ]

  // Check if the current path should be allowed without authentication
  const isPublicPath = publicPaths.some((path) => req.path === path || req.path.startsWith(path))

  if (isPublicPath) {
    console.log(`Public path accessed: ${req.path}`)
    return next()
  }

  next()
})

// Add this middleware right after your session middleware configuration
// This will specifically handle delinquent users accessing the MDPayment page
app.use((req, res, next) => {
  // Check if this is the MDPayment page
  if (req.path === "/MDPayment.html" || req.path === "/Webpages/MDPayment.html") {
    console.log("MDPayment page accessed, setting delinquent flag in session")

    // Set a flag in the session to indicate this is a delinquent user accessing the payment page
    if (!req.session) {
      req.session = {}
    }

    // This flag will help prevent redirect loops
    req.session.isDelinquentPayment = true

    // Force session save to ensure the flag is stored
    if (typeof req.session.save === "function") {
      req.session.save((err) => {
        if (err) {
          console.error("Error saving delinquent session flag:", err)
        }
        return next()
      })
    } else {
      return next()
    }
  } else {
    next()
  }
})

app.use((req, res, next) => {
  // Check if this is the MDPayment page
  if (req.path === "/MDPayment.html" || req.path === "/Webpages/MDPayment.html") {
    console.log("MDPayment page accessed, setting delinquent flag in session")

    // Set a flag in the session to indicate this is a delinquent user accessing the payment page
    if (!req.session) {
      req.session = {}
    }

    // This flag will help prevent redirect loops
    req.session.isDelinquentPayment = true

    // Force session save to ensure the flag is stored
    if (typeof req.session.save === "function") {
      req.session.save((err) => {
        if (err) {
          console.error("Error saving delinquent session flag:", err)
        }
        return next()
      })
    } else {
      return next()
    }
  } else {
    next()
  }
})

// 2. CORS configuration - single declaration
app.use(
  cors({
    origin: process.env.NODE_ENV === "production" ? "https://avidasetting.onrender.com" : "http://localhost:3000",
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Origin", "X-Requested-With", "Content-Type", "Accept", "Authorization"],
  }),
)

// 3. Debug logging middleware
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`)
  console.log("Request Headers:", req.headers)

  // Set proper headers for API requests
  if (req.path.startsWith("/api") || req.headers.accept?.includes("application/json")) {
    res.setHeader("Content-Type", "application/json")
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private")
    res.setHeader("Pragma", "no-cache")
  }

  next()
})

// Replace the existing session middleware configuration with this updated version
app.use(
  session({
    secret: process.env.SESSION_SECRET || "N3$Pxm/mXm1eYY",
    resave: true,
    saveUninitialized: true,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
      httpOnly: true,
      domain: process.env.NODE_ENV === "production" ? "avidasetting.onrender.com" : undefined,
    },
    proxy: true, // Always trust the proxy
  }),
)

// Add this middleware to improve session handling
// Add this right after your session middleware configuration

// Add this middleware right after your session middleware configuration

// Add this middleware right after the session middleware to log session data
app.use((req, res, next) => {
  console.log("Session middleware - Current session:", {
    id: req.sessionID,
    user: req.session?.user,
    cookie: req.session?.cookie,
  })

  // Add a header to help debug authentication issues
  if (req.session && req.session.user) {
    res.setHeader("X-Auth-Status", "authenticated")
    res.setHeader("X-Auth-User", req.session.user.email || "unknown")
    res.setHeader("X-Auth-Role", req.session.user.role || "unknown")
  } else {
    res.setHeader("X-Auth-Status", "unauthenticated")
  }

  next()
})

// Add this middleware right after the session middleware to log session data
app.use((req, res, next) => {
  console.log("Session middleware - Current session:", {
    id: req.sessionID,
    user: req.session?.user,
    cookie: req.session?.cookie,
  })
  next()
})

// And replace it with this:
app.use((req, res, next) => {
  // List of paths that require authentication
  const protectedPaths = [
    "/AdHome.html",
    "/HoHome.html",
    "/admin/",
    "/homeowner/",
    // Add other protected paths here
  ]

  // List of paths that should be accessible without authentication
  const publicPaths = [
    "/login.html",
    "/MDPayment.html",
    "/api/monthly-dues-payment",
    "/api/submit-monthly-payment",
    "/images/",
    "/CSS/",
  ]

  // Check if the current path is public (always allowed)
  const isPublicPath = publicPaths.some((path) => req.path === path || req.path.startsWith(path))

  if (isPublicPath) {
    return next()
  }

  // Check if the current path is protected
  const isProtected = protectedPaths.some((path) => req.path === path || req.path.startsWith(path))

  if (isProtected) {
    // If this is a protected path and user is not logged in, redirect to login
    if (!req.session || !req.session.user) {
      console.log(`Unauthorized access attempt to ${req.path}, redirecting to login`)

      // If it's an API request, return 401
      if (req.path.startsWith("/api/") || req.headers.accept?.includes("application/json")) {
        return res.status(401).json({ success: false, message: "Authentication required" })
      }

      // Otherwise redirect to login page
      return res.redirect("/login.html")
    }

    // For admin paths, check if user has admin role
    if (req.path.startsWith("/admin/") && req.session.user.role !== "admin") {
      console.log(`Non-admin user ${req.session.user.email} attempted to access ${req.path}`)
      return res.status(403).send("Access denied")
    }
  }

  next()
})

// Add this middleware right after the authentication middleware to allow access to MDPayment.html for delinquent users
app.use((req, res, next) => {
  // List of paths that should be accessible even for delinquent users
  const allowedForDelinquentPaths = [
    "/MDPayment.html",
    "/api/monthly-dues-payment",
    "/api/submit-monthly-payment",
    "/images/",
    "/CSS/",
  ]

  // Check if the current path should be allowed for delinquent users
  const isAllowedForDelinquent = allowedForDelinquentPaths.some(
    (path) => req.path === path || req.path.startsWith(path),
  )

  if (isAllowedForDelinquent) {
    return next()
  }

  next()
})

// Add this middleware to serve JavaScript files with the correct MIME type
// Add this right after your other middleware configurations, before your routes
app.use((req, res, next) => {
  // Set the correct MIME type for JavaScript files
  if (req.path.endsWith(".js")) {
    res.setHeader("Content-Type", "application/javascript")
  }
  next()
})

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
})

let database
let activityLogsCollection = null

const allowedOrigins = ["https://capstone-jolin-hamor-pacson.vercel.app", "http://localhost:3000"]

const corsOptions = {
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true)
    } else {
      callback(new Error("Not allowed by CORS"))
    }
  },
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Origin", "X-Requested-With", "Content-Type", "Accept", "Authorization"],
  credentials: true,
  optionsSuccessStatus: 204,
}

function formatTime(timeString) {
  if (!timeString) return ""

  // Remove extra spaces and ensure proper format
  timeString = timeString.replace(/\s+/g, " ").trim()

  // Split time and period
  const [time, period] = timeString.split(" ")
  if (!time || !period) return timeString

  // Add leading zero to hour if needed
  const [hour, minute] = time.split(":")
  const formattedHour = hour.padStart(2, "0")
  const formattedMinute = minute ? minute.padStart(2, "00") : "00"

  return `${formattedHour}:${formattedMinute} ${period}`
}

// Add debug logging to track request flow:

// Specific static file handling with logging

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

// Middleware to attach the database

connectToDatabase().catch(console.error)

// Debug middleware to log all requests

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

// Update the login route to check for delinquent status
// Replace your existing /api/login route with this one
app.post("/api/login", async (req, res) => {
  const { login, password } = req.body

  try {
    const db = await connectToDatabase()
    console.log("Attempting to connect to database...")
    console.log("Connected to database successfully")

    const usersCollection = db.collection("acc")
    const homeownersCollection = db.collection("homeowners")

    if (!login || !password) {
      return res.status(400).json({
        success: false,
        message: "Email and password are required",
      })
    }

    console.log("Searching for user...")
    // Find the user
    const user = await usersCollection.findOne({
      $or: [
        { email: { $regex: new RegExp(`^${login}$`, "i") } },
        { username: { $regex: new RegExp(`^${login}$`, "i") } },
      ],
    })

    if (!user) {
      console.log("User not found")
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      })
    }

    console.log("User found, comparing passwords...")
    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password)

    if (!isValidPassword) {
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      })
    }

    // Check if user is a homeowner
    if (user.role !== "admin") {
      // Check if homeowner is delinquent
      const homeowner = await homeownersCollection.findOne({ email: user.email })

      if (homeowner && (homeowner.paymentStatus === "Delinquent" || homeowner.homeownerStatus === "Delinquent")) {
        // User is delinquent, return special response
        console.log(`User ${user.email} is delinquent, returning delinquent status`)
        return res.json({
          success: false,
          isDelinquent: true,
          username: user.username,
          email: user.email,
          dueAmount: homeowner.dueAmount || "5000.00", // Default amount if not specified
          message: "Account is delinquent. Please pay your monthly dues.",
        })
      }
    }

    // Set user data in session
    req.session.user = {
      username: user.username,
      email: user.email,
      role: user.role || "homeowner",
    }

    // Force session save
    req.session.save((err) => {
      if (err) {
        console.error("Error saving session:", err)
        return res.status(500).json({
          success: false,
          message: "Error saving session",
        })
      }

      console.log("Session saved successfully:", req.sessionID)
      console.log("Session data:", req.session)

      // Log successful login
      logActivity("login", `User ${user.username} logged in successfully`)

      res.json({
        success: true,
        username: user.username,
        email: user.email,
        role: user.role || "homeowner",
        redirectUrl: user.role === "admin" ? "/Webpages/AdHome.html" : "/Webpages/HoHome.html",
      })
    })
  } catch (error) {
    console.error("Login error:", error)
    res.status(500).json({
      success: false,
      message: "An error occurred during login",
      error: error.message,
    })
  }
})

app.get("/api/check-auth", (req, res) => {
  console.log("Auth check - Session:", req.session)
  console.log("Auth check - Cookies:", req.headers.cookie)

  // Add debug headers to response
  res.setHeader("X-Debug-Session-ID", req.sessionID || "none")
  res.setHeader("X-Debug-Has-Session", req.session ? "yes" : "no")
  res.setHeader("X-Debug-Has-User", req.session && req.session.user ? "yes" : "no")

  // Emergency override for redirect loops
  const forceAuth = req.query.force === "true"

  if (forceAuth) {
    console.log("WARNING: Force authentication requested")
    return res.json({
      authenticated: true,
      user: {
        username: "Admin User",
        email: "admin@example.com",
        role: "admin",
      },
      forced: true,
      sessionID: req.sessionID,
      timestamp: new Date().toISOString(),
    })
  }

  if (req.session && req.session.user) {
    return res.json({
      authenticated: true,
      user: {
        username: req.session.user.username,
        email: req.session.user.email,
        role: req.session.user.role,
      },
      sessionID: req.sessionID,
      timestamp: new Date().toISOString(),
    })
  }

  return res.json({
    authenticated: false,
    sessionID: req.sessionID,
    timestamp: new Date().toISOString(),
  })
})

// Add a special endpoint to force authentication (for breaking loops)
app.get("/api/force-auth", (req, res) => {
  if (!req.session) {
    req.session = {}
  }

  req.session.user = {
    id: "emergency-override",
    email: "admin@example.com",
    username: "Admin User",
    role: "admin",
  }

  req.session.save((err) => {
    if (err) {
      console.error("Error saving emergency session:", err)
      return res.status(500).json({
        success: false,
        message: "Failed to create emergency session",
      })
    }

    res.json({
      success: true,
      message: "Emergency authentication created",
      user: req.session.user,
    })
  })
})

app.post("/api/check-delinquent-status", async (req, res) => {
  const { login, password } = req.body

  try {
    const db = await connectToDatabase()
    const usersCollection = db.collection("acc")
    const homeownersCollection = db.collection("homeowners")

    // Find user by email or username
    const user = await usersCollection.findOne({
      $or: [
        { email: { $regex: new RegExp(`^${login}$`, "i") } },
        { username: { $regex: new RegExp(`^${login}$`, "i") } },
      ],
    })

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      })
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password)

    if (!isValidPassword) {
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      })
    }

    // Check if user is a homeowner
    if (user.role === "homeowner" || !user.role) {
      // Check delinquent status
      const homeowner = await homeownersCollection.findOne({ email: user.email })

      if (homeowner && (homeowner.paymentStatus === "Delinquent" || homeowner.homeownerStatus === "Delinquent")) {
        // User is delinquent, return special response
        return res.json({
          success: false,
          isDelinquent: true,
          username: user.username,
          dueAmount: homeowner.dueAmount || "5000.00", // Default amount if not specified
          message: "Your account has outstanding dues that need to be paid.",
        })
      }
    }

    // Normal successful login
    req.session.user = {
      username: user.username,
      email: user.email,
      role: user.role || "homeowner",
    }

    await logActivity("login", `User ${user.username} logged in successfully`)

    res.json({
      success: true,
      username: user.username,
      email: user.email,
      role: user.role || "homeowner",
      redirectUrl: user.role === "admin" ? "/AdHome.html" : "/HoHome.html",
    })
  } catch (error) {
    console.error("Login error:", error)
    res.status(500).json({
      success: false,
      message: "An error occurred during login",
      error: error.message,
    })
  }
})

app.post("/api/monthly-dues-payment", upload.single("receipt"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: "No receipt file uploaded",
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
      userEmail: req.body.userEmail,
      userName: req.body.userName,
      amount: req.body.finalAmount,
      paymentMethod: req.body.paymentMethod,
      receiptImage: `data:${mimeType};base64,${base64Image}`,
      status: "pending", // Initial status is pending until admin approves
      timestamp: new Date(),
    }

    // Save to MongoDB
    const db = await connectToDatabase()
    const paymentsCollection = db.collection("monthlyPayments")
    const result = await paymentsCollection.insertOne(paymentData)

    // Update homeowner status if payment is submitted
    const homeownersCollection = db.collection("homeowners")
    await homeownersCollection.updateOne(
      { email: paymentData.userEmail },
      {
        $set: {
          paymentStatus: "pending",
          lastPaymentId: result.insertedId,
          lastPaymentDate: new Date(),
        },
      },
    )

    // Cleanup the temporary file
    fs.unlinkSync(filePath)

    // Create notification for admin
    await createNotification(
      "admin@avidadb.com", // Admin email
      "monthly_payment",
      `New monthly payment submitted by ${paymentData.userName} (${paymentData.userEmail})`,
      result.insertedId,
    )

    res.status(200).json({
      success: true,
      message: "Payment submitted successfully! Admin will review your payment.",
    })
  } catch (err) {
    console.error("Error handling monthly payment:", err)

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

app.post("/api/submit-monthly-payment", upload.single("receipt"), async (req, res) => {
  try {
    const { userEmail, userName, finalAmount, paymentMethod } = req.body

    if (!userEmail || !finalAmount || !paymentMethod || !req.file) {
      return res.status(400).json({ success: false, message: "Missing required fields" })
    }

    // Create payment record
    const payment = {
      email: userEmail,
      username: userName,
      amount: Number.parseFloat(finalAmount),
      paymentMethod,
      receiptPath: `/uploads/receipts/${req.file.filename}`,
      status: "pending",
      submittedAt: new Date(),
    }

    // Insert payment record
    const db = await connectToDatabase()
    const paymentsCollection = db.collection("monthlyPayments")
    const result = await paymentsCollection.insertOne(payment)

    // Create notification for admin
    await db.collection("notifications").insertOne({
      recipient: "admin",
      message: `New monthly dues payment from ${userName} (${userEmail})`,
      type: "payment",
      relatedId: result.insertedId,
      timestamp: new Date(),
      read: false,
    })

    return res.json({
      success: true,
      message: "Payment submitted successfully",
      paymentId: result.insertedId,
    })
  } catch (error) {
    console.error("Error submitting payment:", error)
    return res.status(500).json({ success: false, message: "Server error" })
  }
})

app.get("/api/monthly-payments", async (req, res) => {
  try {
    const { status, search } = req.query
    const db = await connectToDatabase()
    const paymentsCollection = db.collection("monthlypayments")

    // Build query based on filters
    const query = { paymentType: "monthlyDues" }

    if (status && status !== "all") {
      query.status = status
    }

    if (search) {
      query.$or = [{ userEmail: { $regex: search, $options: "i" } }, { userName: { $regex: search, $options: "i" } }]
    }

    // Get payments
    const payments = await paymentsCollection.find(query).sort({ timestamp: -1 }).toArray()

    res.json({
      success: true,
      payments,
    })
  } catch (error) {
    console.error("Error fetching monthly payments:", error)
    res.status(500).json({
      success: false,
      message: "Error fetching payments",
      payments: [],
    })
  }
})

app.post("/api/monthly-payments/:id/approve", async (req, res) => {
  try {
    const { id } = req.params
    const db = await connectToDatabase()
    const paymentsCollection = db.collection("monthlypayments")
    const homeownersCollection = db.collection("homeowners")

    // Find the payment
    const payment = await paymentsCollection.findOne({ _id: new ObjectId(id) })

    if (!payment) {
      return res.status(404).json({
        success: false,
        message: "Payment not found",
      })
    }

    // Update payment status
    await paymentsCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: { status: "approved", approvedAt: new Date() } },
    )

    // Update homeowner status
    await homeownersCollection.updateOne(
      { email: payment.userEmail },
      { $set: { paymentStatus: "active", dueAmount: "0.00" } },
    )

    // Log the approval
    await logActivity("paymentApproval", `Monthly dues payment for ${payment.userEmail} approved`)

    // Create notification for the user
    await createNotification(
      payment.userEmail,
      "payment_approved",
      "Your monthly dues payment has been approved. Your account is now active.",
      payment._id,
    )

    res.json({
      success: true,
      message: "Payment approved successfully",
    })
  } catch (error) {
    console.error("Error approving payment:", error)
    res.status(500).json({
      success: false,
      message: "Error approving payment",
    })
  }
})

app.post("/api/monthly-payments/:id/reject", async (req, res) => {
  try {
    const { id } = req.params
    const { reason } = req.body
    const db = await connectToDatabase()
    const paymentsCollection = db.collection("monthlypayments")

    // Find the payment
    const payment = await paymentsCollection.findOne({ _id: new ObjectId(id) })

    if (!payment) {
      return res.status(404).json({
        success: false,
        message: "Payment not found",
      })
    }

    // Update payment status
    await paymentsCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: { status: "rejected", rejectedAt: new Date(), rejectionReason: reason } },
    )

    // Log the rejection
    await logActivity("paymentRejection", `Monthly dues payment for ${payment.userEmail} rejected: ${reason}`)

    // Create notification for the user
    await createNotification(
      payment.userEmail,
      "payment_rejected",
      `Your monthly dues payment was rejected. Reason: ${reason}`,
      payment._id,
    )

    res.json({
      success: true,
      message: "Payment rejected successfully",
    })
  } catch (error) {
    console.error("Error rejecting payment:", error)
    res.status(500).json({
      success: false,
      message: "Error rejecting payment",
    })
  }
})

app.post("/api/review-monthly-payment", async (req, res) => {
  try {
    // Check if user is authenticated and is admin
    if (!req.session || !req.session.user || req.session.user.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Unauthorized",
      })
    }

    const { paymentId, action, notes } = req.body

    if (!paymentId || !action || !["approve", "reject"].includes(action)) {
      return res.status(400).json({
        success: false,
        message: "Invalid request parameters",
      })
    }

    const db = await connectToDatabase()
    const paymentsCollection = db.collection("monthlyPayments")
    const usersCollection = db.collection("users")

    // Find the payment
    const payment = await paymentsCollection.findOne({ _id: new ObjectId(paymentId) })

    if (!payment) {
      return res.status(404).json({
        success: false,
        message: "Payment not found",
      })
    }

    // Update payment status
    await paymentsCollection.updateOne(
      { _id: new ObjectId(paymentId) },
      {
        $set: {
          status: action === "approve" ? "approved" : "rejected",
          reviewedBy: req.session.user.email,
          reviewTimestamp: new Date(),
          reviewNotes: notes || "",
        },
      },
    )

    // If approved, update user's delinquent status
    if (action === "approve") {
      await usersCollection.updateOne(
        { email: payment.userEmail },
        {
          $set: {
            isDelinquent: false,
            lastPaymentDate: new Date(),
            lastPaymentAmount: payment.amount,
          },
        },
      )

      // Create notification for user
      await createNotification(
        payment.userEmail,
        "payment_approved",
        `Your monthly dues payment of ₱${payment.amount} for ${payment.month} ${payment.year} has been approved.`,
        payment._id.toString(),
        "Monthly Dues Payment Approved",
        null,
        { isMonthlyPayment: true },
      )
    } else {
      // Create notification for rejection
      await createNotification(
        payment.userEmail,
        "payment_rejected",
        `Your monthly dues payment of ₱${payment.amount} for ${payment.month} ${payment.year} has been rejected. Reason: ${notes || "No reason provided"}`,
        payment._id.toString(),
        "Monthly Dues Payment Rejected",
        null,
        { isMonthlyPayment: true },
      )
    }

    res.json({
      success: true,
      message: `Payment ${action === "approve" ? "approved" : "rejected"} successfully`,
    })
  } catch (error) {
    console.error(`Error ${req.body.action}ing monthly payment:`, error)
    res.status(500).json({
      success: false,
      message: `Failed to ${req.body.action} payment`,
    })
  }
})

async function logActivity(action, details) {
  try {
    const db = await connectToDatabase()
    if (!activityLogsCollection) {
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

  // Format the times
  const formattedStartTime = formatTime(startTime)
  const formattedEndTime = formatTime(endTime)

  const userEmail = req.session.user.email

  try {
    const db = await connectToDatabase()
    const eventsCollection = db.collection("events")

    const newEvent = {
      HomeownerName,
      userEmail,
      eventName,
      eventDate,
      startTime: formattedStartTime,
      endTime: formattedEndTime,
      amenity,
      eventType,
      guests: {
        number: guests.number,
        names: guests.names,
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

app.post("/api/submit-monthly-payment", upload.single("receipt"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: "No receipt file uploaded",
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
      userEmail: req.body.userEmail,
      userName: req.body.userName,
      amount: req.body.finalAmount,
      paymentMethod: req.body.paymentMethod,
      receiptImage: `data:${mimeType};base64,${base64Image}`,
      status: "pending", // Initial status is pending until admin approves
      timestamp: new Date(),
    }

    // Save to MongoDB
    const db = await connectToDatabase()
    const paymentsCollection = db.collection("monthlyPayments")
    await paymentsCollection.insertOne(paymentData)

    // Cleanup the temporary file
    fs.unlinkSync(filePath)

    // Create notification for admin
    await createNotification(
      "admin@avidadb.com", // Admin email
      "monthly_payment",
      `New monthly payment submitted by ${paymentData.userName} (${paymentData.userEmail})`,
      paymentData._id,
    )

    res.status(200).json({
      success: true,
      message: "Payment submitted successfully! Admin will review your payment.",
    })
  } catch (err) {
    console.error("Error handling monthly payment:", err)

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

app.post("/api/process-payment", async (req, res) => {
  try {
    // Check if user is authenticated as admin
    if (!req.session || req.session.role !== "admin") {
      return res.status(401).json({ success: false, message: "Unauthorized" })
    }

    const { paymentId, action, reason } = req.body

    if (!paymentId || !action || (action !== "approve" && action !== "reject")) {
      return res.status(400).json({ success: false, message: "Invalid request parameters" })
    }

    // Find the payment
    const db = await connectToDatabase()
    const paymentsCollection = db.collection("monthlyPayments")
    const payment = await paymentsCollection.findOne({ _id: ObjectId(paymentId) })

    if (!payment) {
      return res.status(404).json({ success: false, message: "Payment not found" })
    }

    if (payment.status !== "pending") {
      return res.status(400).json({ success: false, message: "Payment has already been processed" })
    }

    const rejectionReason = action === "reject" ? reason || "No reason provided" : null

    // Update payment status
    await paymentsCollection.updateOne(
      { _id: ObjectId(paymentId) },
      {
        $set: {
          status: action === "approve" ? "approved" : "rejected",
          processedAt: new Date(),
          processedBy: req.session.username,
          rejectionReason,
        },
      },
    )

    // If approved, update user's delinquent status
    if (action === "approve") {
      const homeownersCollection = db.collection("homeowners")
      await homeownersCollection.updateOne(
        { email: payment.email },
        { $set: { isDelinquent: false, lastPaymentDate: new Date() } },
      )
    }

    // Create notification for the user
    const notificationsCollection = db.collection("notifications")
    await notificationsCollection.insertOne({
      recipient: payment.email,
      message:
        action === "approve"
          ? "Your monthly dues payment has been approved. You can now log in to the system."
          : `Your monthly dues payment has been rejected. Reason: ${rejectionReason}`,
      type: "payment",
      relatedId: payment._id,
      timestamp: new Date(),
      read: false,
    })

    // Log the activity
    const activityLogsCollection = db.collection("activityLogs")
    await activityLogsCollection.insertOne({
      action: action === "approve" ? "paymentApproval" : "paymentRejection",
      details: `${action === "approve" ? "Approved" : "Rejected"} payment from ${payment.username} (${payment.email})`,
      performedBy: req.session.username,
      timestamp: new Date(),
    })

    return res.json({
      success: true,
      message: action === "approve" ? "Payment approved successfully" : "Payment rejected successfully",
    })
  } catch (error) {
    console.error("Error processing payment:", error)
    return res.status(500).json({ success: false, message: "Server error" })
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
      // In the profile route, change:
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

// Update the pending-events endpoint - place this BEFORE any static file middleware
app.get("/api/pending-events", async (req, res) => {
  console.log("Pending events request received")

  try {
    const db = await connectToDatabase()
    console.log("Database connected")

    const eventsCollection = db.collection("events")
    // If you're using a status field to determine pending events
    const pendingEvents = await eventsCollection.find({ status: { $ne: "approved" } }).toArray()
    // If you don't have a status field, just get all events from the events collection
    // const pendingEvents = await eventsCollection.find({}).toArray()

    console.log("Found pending events:", pendingEvents.length)

    // Set headers explicitly
    res.setHeader("Content-Type", "application/json")
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private")
    res.setHeader("Pragma", "no-cache")

    return res.json({
      success: true,
      events: pendingEvents || [],
    })
  } catch (error) {
    console.error("Error fetching pending events:", error)
    return res.status(500).json({
      success: false,
      message: "Error fetching events",
      error: error.message,
      events: [],
    })
  }
})

// Update the approved-events endpoint similarly
app.get("/api/approved-events", async (req, res) => {
  try {
    const db = await connectToDatabase()
    const eventsCollection = db.collection("aevents")

    const events = await eventsCollection.find({ status: "approved" }).sort({ eventDate: 1 }).toArray()

    res.json({
      success: true,
      events,
    })
  } catch (error) {
    console.error("Error fetching approved events:", error)
    res.status(500).json({
      success: false,
      message: "Error fetching approved events",
      error: error.message,
    })
  }
})

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

// Update the createNotification function to properly set the notification type for admin responses
async function createNotification(userEmail, type, message, relatedId, subject, amenity, eventDetails = {}) {
  try {
    const db = await connectToDatabase()
    const notificationsCollection = db.collection("notifications")

    // Determine if this is an admin response/concern notification
    const isAdminResponse =
      type === "concern" ||
      type === "new_concern" ||
      (subject && subject.toLowerCase().includes("concern")) ||
      (message && message.toLowerCase().includes("concern"))

    // If it's an admin response but the type isn't set correctly, fix it
    if (isAdminResponse && type !== "concern" && type !== "new_concern") {
      type = "concern"
    }

    // Check if this is an event notification that could be a free event or already paid
    let isFreeEvent = false
    let isAlreadyPaid = false
    let paymentStatus = "pending"

    // Only process these checks for event-related notifications
    if (!isAdminResponse) {
      // Check event type if available
      if (eventDetails.eventType) {
        const freeEventTypes = ["birthday", "meeting", "community", "free"]
        isFreeEvent = freeEventTypes.some((keyword) => eventDetails.eventType.toLowerCase().includes(keyword))
      }

      // Check if payment has already been made
      if (eventDetails.paymentStatus === "paid" || eventDetails.isPaid === true || type === "payment_confirmed") {
        isAlreadyPaid = true
        paymentStatus = "paid"
      }

      // Check message and event name for free event keywords
      if (type === "payment_required" && !isFreeEvent && !isAlreadyPaid) {
        // Check if the message indicates a free event
        const lowerCaseMsg = (message || "").toLowerCase()
        const eventName = (eventDetails.eventName || "").toLowerCase()

        // Check for keywords indicating free events
        const freeEventKeywords = ["birthday", "meeting", "celebration", "community event"]
        isFreeEvent = freeEventKeywords.some((keyword) => lowerCaseMsg.includes(keyword) || eventName.includes(keyword))

        if (isFreeEvent) {
          paymentStatus = "free"
        }
      }

      // Modify notification type and message based on event type
      if (isFreeEvent || isAlreadyPaid) {
        // Change type for free events
        if (isFreeEvent && type === "payment_required") {
          type = "event_confirmed"
        }

        // Modify the message to indicate viewing details instead of payment
        if (message) {
          if (message.includes("Proceed to payment") || message.includes("proceed to payment")) {
            message = message.replace(/Proceed to payment|proceed to payment/g, "See event details here")
          }
        }
      }
    }

    // If related ID is an ObjectId, convert to string for consistent storage
    let relatedIdStr = null
    if (relatedId) {
      if (relatedId instanceof ObjectId) {
        relatedIdStr = relatedId.toString()
      } else if (typeof relatedId !== "string") {
        relatedIdStr = String(relatedId)
      } else {
        relatedIdStr = relatedId
      }
    }

    // Create the notification with all available data
    const notification = {
      userEmail,
      type,
      message,
      relatedId: relatedIdStr,
      subject: subject,
      amenity: amenity || eventDetails.amenity || null,
      eventName: eventDetails.eventName || null,
      eventDate: eventDetails.eventDate || null,
      startTime: eventDetails.startTime || null,
      endTime: eventDetails.endTime || null,
      paymentStatus: paymentStatus,
      timestamp: new Date(),
      read: false,
      isAdminResponse: isAdminResponse, // Add a flag to easily identify admin responses
    }

    console.log("Creating notification:", JSON.stringify(notification))
    const result = await notificationsCollection.insertOne(notification)
    return result.insertedId
  } catch (error) {
    console.error("Error creating notification:", error)
    return null
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

// Add this to server.js
app.get("/api/fix-notification-types", async (req, res) => {
  try {
    const db = await connectToDatabase()
    const notificationsCollection = db.collection("notifications")
    const eventpaymentsCollection = db.collection("eventpayments")

    // Get all notifications
    const notifications = await notificationsCollection.find({}).toArray()

    let fixedCount = 0

    // Process each notification
    for (const notification of notifications) {
      try {
        // Skip if no eventName or eventDate
        if (!notification.eventName || !notification.eventDate) continue

        // Check if payment exists for this event
        const payment = await eventpaymentsCollection.findOne({
          eventName: notification.eventName,
          eventDate: notification.eventDate,
        })

        let updateNeeded = false
        const updateData = {}

        // If payment exists but notification type is payment_required, update it
        if (payment && notification.type === "payment_required") {
          updateData.type = "payment_confirmed"
          updateData.message = `Your payment for event "${notification.eventName}" has been confirmed.`
          updateNeeded = true
        }

        // If notification message mentions payment but type is not set correctly
        if (notification.message && notification.message.includes("proceed with the payment")) {
          if (!payment && notification.type !== "payment_required") {
            updateData.type = "payment_required"
            updateNeeded = true
          } else if (payment && notification.type !== "payment_confirmed") {
            updateData.type = "payment_confirmed"
            updateData.message = `Your payment for event "${notification.eventName}" has been confirmed.`
            updateNeeded = true
          }
        }

        // Update if needed
        if (updateNeeded) {
          await notificationsCollection.updateOne({ _id: notification._id }, { $set: updateData })
          fixedCount++
        }
      } catch (error) {
        console.error(`Error processing notification ${notification._id}:`, error)
      }
    }

    res.json({
      success: true,
      message: `Fixed ${fixedCount} of ${notifications.length} notifications`,
    })
  } catch (error) {
    console.error("Error fixing notification types:", error)
    res.status(500).json({
      success: false,
      error: error.message,
    })
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

// Update the existing approve event route

app.get("/api/event/:id", async (req, res) => {
  try {
    const eventId = req.params.id

    // Check if eventId is provided
    if (!eventId) {
      return res.status(400).json({
        success: false,
        message: "Event ID is required",
      })
    }

    const db = await connectToDatabase()
    const eventsCollection = db.collection("events")

    // Convert string ID to ObjectId if using MongoDB's ObjectId
    let objectId
    try {
      objectId = new ObjectId(eventId)
    } catch (e) {
      return res.status(400).json({
        success: false,
        message: "Invalid event ID format",
      })
    }

    // Find the event by ID
    const event = await eventsCollection.findOne({ _id: objectId })

    if (!event) {
      return res.status(404).json({
        success: false,
        message: "Event not found",
      })
    }

    res.json({
      success: true,
      event: event,
    })
  } catch (error) {
    console.error("Error fetching event details:", error)
    res.status(500).json({
      success: false,
      message: "Server error while fetching event details",
      error: error.message,
    })
  }
})
// Add this to server.js
app.get("/api/debug/notifications", async (req, res) => {
  try {
    const db = await connectToDatabase()
    const notificationsCollection = db.collection("notifications")

    // Get 10 most recent notifications
    const notifications = await notificationsCollection.find({}).sort({ timestamp: -1 }).limit(10).toArray()

    res.json({
      success: true,
      count: notifications.length,
      notifications: notifications,
    })
  } catch (error) {
    console.error("Error debugging notifications:", error)
    res.status(500).json({
      success: false,
      error: error.message,
    })
  }
})

app.put("/approveEvent/:eventName", async (req, res) => {
  const { eventName } = req.params

  try {
    const db = await connectToDatabase()
    const eventsCollection = db.collection("events")
    const aeventsCollection = db.collection("aevents")

    const event = await eventsCollection.findOne({ eventName })

    if (!event) {
      return res.status(404).json({ success: false, message: "Event not found." })
    }

    // Format times properly
    const formattedStartTime = formatTime(event.startTime || "")
    const formattedEndTime = formatTime(event.endTime || "")

    // Create approved event with formatted times
    const approvedEvent = {
      ...event,
      startTime: formattedStartTime,
      endTime: formattedEndTime,
      status: "approved",
      approvedAt: new Date(),
    }

    const result = await aeventsCollection.insertOne(approvedEvent)
    await eventsCollection.deleteOne({ eventName })

    // Create a well-formatted subject line
    const timeInfo = formattedStartTime && formattedEndTime ? `${formattedStartTime}-${formattedEndTime}` : ""
    const subject = `${eventName} on ${event.eventDate} ${timeInfo}`.trim()

    // Create notification with complete details
    await createNotification(
      event.userEmail,
      "payment_required",
      `Your event "${eventName}" has been approved. Please proceed with the payment.`,
      result.insertedId,
      subject,
      event.amenity,
    )

    res.json({ success: true, message: "Event approved. User notified for payment." })
  } catch (error) {
    console.error("Error approving event:", error)
    res.status(500).json({ success: false, message: "Server error while approving event." })
  }
})

app.post("/api/approve-event", async (req, res) => {
  const { eventName } = req.body

  if (!eventName) {
    return res.status(400).json({
      success: false,
      message: "Event name is required",
    })
  }

  try {
    const db = await connectToDatabase()
    const eventsCollection = db.collection("events")
    const aeventsCollection = db.collection("aevents")

    // Find the event in the events collection
    const event = await eventsCollection.findOne({ eventName })

    if (!event) {
      return res.status(404).json({
        success: false,
        message: "Event not found",
      })
    }

    // Format times before moving to approved events
    const approvedEvent = {
      ...event,
      startTime: formatTime(event.startTime),
      endTime: formatTime(event.endTime),
      approvedAt: new Date(),
      status: "approved",
    }

    await aeventsCollection.insertOne(approvedEvent)
    await eventsCollection.deleteOne({ eventName })

    if (event.userEmail) {
      const timeRange = `${approvedEvent.startTime}-${approvedEvent.endTime}`
      await createNotification(
        event.userEmail,
        "payment_required",
        `Your event "${eventName}" has been approved. Please proceed with the payment.`,
        approvedEvent._id.toString(),
        `${eventName} on ${event.eventDate} ${timeRange}`,
        event.amenity,
      )
    }

    await logActivity("eventApproval", `Event ${eventName} approved`)

    res.json({
      success: true,
      message: "Event approved successfully",
    })
  } catch (error) {
    console.error("Error approving event:", error)
    res.status(500).json({
      success: false,
      message: "Server error while approving event",
      error: error.message,
    })
  }
})

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

//Submit Concern

app.get("/api/repair-notifications", async (req, res) => {
  try {
    const db = await connectToDatabase()
    const notificationsCollection = db.collection("notifications")
    const aeventsCollection = db.collection("aevents")

    // Get all notifications that might need repair
    const notifications = await notificationsCollection
      .find({
        $or: [
          { eventDate: { $exists: false } },
          { startTime: { $exists: false } },
          { endTime: { $exists: false } },
          { amenity: { $exists: false } },
        ],
      })
      .toArray()

    console.log(`Found ${notifications.length} notifications that need repair`)

    let repaired = 0

    // Process each notification
    for (const notification of notifications) {
      // Skip if no relatedId
      if (!notification.relatedId) continue

      try {
        // Try to find the related event
        let event = null
        try {
          const objectId = new ObjectId(notification.relatedId)
          event = await aeventsCollection.findOne({ _id: objectId })
        } catch (err) {
          // Not a valid ObjectId, try other methods
        }

        // If event not found by ID, try by name
        if (!event && notification.eventName) {
          event = await aeventsCollection.findOne({ eventName: notification.eventName })
        }

        // If event found, update the notification
        if (event) {
          const updateData = {
            eventName: event.eventName,
            eventDate: event.eventDate,
            startTime: event.startTime,
            endTime: event.endTime,
            amenity: event.amenity,
          }

          // Create a better subject line
          const timeInfo = event.startTime && event.endTime ? `${event.startTime}-${event.endTime}` : ""
          const subject = `${event.eventName} on ${event.eventDate} ${timeInfo}`.trim()
          updateData.subject = subject

          await notificationsCollection.updateOne({ _id: notification._id }, { $set: updateData })

          repaired++
        }
      } catch (error) {
        console.error(`Error repairing notification ${notification._id}:`, error)
      }
    }

    res.json({
      success: true,
      message: `Repaired ${repaired} of ${notifications.length} notifications`,
    })
  } catch (error) {
    console.error("Error repairing notifications:", error)
    res.status(500).json({
      success: false,
      error: error.message,
    })
  }
})

// Add this to server.js
app.get("/api/event-by-name/:eventName", async (req, res) => {
  const { eventName } = req.params

  try {
    console.log("Fetching event with name:", eventName)

    const db = await connectToDatabase()
    const aeventsCollection = db.collection("aevents")

    const event = await aeventsCollection.findOne({ eventName })

    if (event) {
      console.log("Event found by name:", event)
      res.json({ success: true, event })
    } else {
      console.log("No event found with name:", eventName)
      res.status(404).json({ success: false, message: "Event not found" })
    }
  } catch (error) {
    console.error("Error fetching event details:", error)
    res.status(500).json({
      success: false,
      message: "Server error while fetching event details",
      error: error.message,
    })
  }
})

// Add this to server.js
async function cleanupOrphanedNotifications() {
  try {
    const db = await connectToDatabase()
    const notificationsCollection = db.collection("notifications")
    const aeventsCollection = db.collection("aevents")

    // Find notifications with relatedId that don't exist in events
    const notifications = await notificationsCollection
      .find({
        relatedId: { $exists: true, $ne: null },
      })
      .toArray()

    let orphanCount = 0

    for (const notification of notifications) {
      try {
        // Skip if no relatedId
        if (!notification.relatedId) continue

        // Check if related event exists
        let eventExists = false
        try {
          const objectId = new ObjectId(notification.relatedId)
          const event = await aeventsCollection.findOne({ _id: objectId })
          eventExists = !!event
        } catch (err) {
          // Not a valid ObjectId
        }

        // If event doesn't exist and notification is older than 30 days, delete it
        if (!eventExists) {
          const thirtyDaysAgo = new Date()
          thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30)

          if (notification.timestamp < thirtyDaysAgo) {
            await notificationsCollection.deleteOne({ _id: notification._id })
            orphanCount++
          }
        }
      } catch (error) {
        console.error(`Error processing notification ${notification._id}:`, error)
      }
    }

    console.log(`Cleaned up ${orphanCount} orphaned notifications`)
  } catch (error) {
    console.error("Error cleaning up orphaned notifications:", error)
  }
}

// Run cleanup once a week
schedule.scheduleJob("0 0 * * 0", cleanupOrphanedNotifications)

app.post("/addconcern", async (req, res) => {
  try {
    const { username, email, subject, message, createdAt, file } = req.body

    if (!email || !subject || !message) {
      return res.status(400).json({
        success: false,
        message: "Missing required fields",
      })
    }

    const db = await connectToDatabase()
    const concernsCollection = db.collection("concerns")

    const newConcern = {
      username,
      email,
      subject,
      message,
      createdAt: createdAt || new Date().toISOString(),
      status: "pending",
      file: file || null,
    }

    const result = await concernsCollection.insertOne(newConcern)

    // Create a notification for the admin
    await createNotification(
      "admin@example.com", // Admin email - replace with actual admin email
      "new_concern",
      `New concern submitted by ${username || email}: "${subject}"`,
      result.insertedId.toString(),
      `New Concern: ${subject}`,
      null,
    )

    res.json({
      success: true,
      message: "Concern submitted successfully",
      concernId: result.insertedId,
    })
  } catch (error) {
    console.error("Error adding concern:", error)
    res.status(500).json({
      success: false,
      message: "Server error while adding concern",
      error: error.message,
    })
  }
})
//Concern Table

app.get("/getConcerns", async (req, res) => {
  try {
    console.log("Fetching concerns...")
    const db = await connectToDatabase()

    // Try both possible collection names
    let collection
    let collectionName

    try {
      // First try lowercase
      collection = db.collection("concerns")
      const count = await collection.countDocuments()
      console.log(`Found ${count} concerns in 'concerns' collection`)
      collectionName = "concerns"

      if (count === 0) {
        // If empty, try capitalized version
        const capitalizedCollection = db.collection("Concerns")
        const capitalizedCount = await capitalizedCollection.countDocuments()
        console.log(`Found ${capitalizedCount} concerns in 'Concerns' collection`)

        if (capitalizedCount > 0) {
          collection = capitalizedCollection
          collectionName = "Concerns"
        }
      }
    } catch (err) {
      console.error("Error checking concerns collection:", err)
      // Try capitalized as fallback
      collection = db.collection("Concerns")
      collectionName = "Concerns"
    }

    console.log(`Using collection: ${collectionName}`)

    const page = Number.parseInt(req.query.page) || 1
    const limit = Number.parseInt(req.query.limit) || 5
    const skip = (page - 1) * limit

    // Get total count for pagination
    const totalConcerns = await collection.countDocuments()
    console.log(`Total concerns: ${totalConcerns}`)

    // Get concerns with pagination
    const concerns = await collection.find({}).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray()

    console.log(`Retrieved ${concerns.length} concerns for page ${page}`)

    // Log the first concern for debugging
    if (concerns.length > 0) {
      console.log("Sample concern:", JSON.stringify(concerns[0], null, 2))
    }

    res.json({
      success: true,
      concerns,
      currentPage: page,
      totalPages: Math.ceil(totalConcerns / limit) || 1,
    })
  } catch (error) {
    console.error("Error fetching concerns:", error)
    res.status(500).json({
      success: false,
      message: "Failed to fetch concerns",
      error: error.message,
    })
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

    const db = await connectToDatabase()
    const activityLogsCollection = db.collection("activityLogs")

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
    res.status(500).json({
      error: "Failed to fetch recent activity",
      message: error.message,
    })
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

app.get("/api/user-events/:email", async (req, res) => {
  try {
    const userEmail = req.params.email

    if (!userEmail) {
      return res.status(400).json({
        success: false,
        message: "User email is required",
      })
    }

    const db = await connectToDatabase()
    const eventsCollection = db.collection("events")

    // Find events by user email
    const events = await eventsCollection
      .find({
        userEmail: userEmail,
      })
      .sort({ eventDate: -1 })
      .toArray()

    res.json({
      success: true,
      events: events,
    })
  } catch (error) {
    console.error("Error fetching user events:", error)
    res.status(500).json({
      success: false,
      message: "Server error while fetching user events",
      error: error.message,
    })
  }
})

app.get("/api/event/:eventId", async (req, res) => {
  const { eventId } = req.params

  try {
    console.log("Fetching event with ID:", eventId)

    const db = await connectToDatabase()
    console.log("Connected to database:", db.databaseName)

    const aeventsCollection = db.collection("aevents")
    const notificationsCollection = db.collection("notifications")

    // Try multiple approaches to find the event
    let event = null

    // First try: Direct ObjectId lookup
    try {
      const objectId = new ObjectId(eventId)
      event = await aeventsCollection.findOne({ _id: objectId })
      console.log("ObjectId lookup result:", event ? "Found" : "Not found")
    } catch (err) {
      console.log("Invalid ObjectId format, trying string comparison")
    }

    // Second try: String comparison with _id
    if (!event) {
      const allEvents = await aeventsCollection.find({}).limit(20).toArray()
      event = allEvents.find((e) => e._id.toString() === eventId)
      console.log("String _id comparison result:", event ? "Found" : "Not found")
    }

    // Third try: Look by eventName
    if (!event) {
      event = await aeventsCollection.findOne({ eventName: eventId })
      console.log("eventName lookup result:", event ? "Found" : "Not found")
    }

    // Fourth try: Find the notification and get user email
    if (!event) {
      console.log("Trying to find notification with relatedId:", eventId)
      const notification = await notificationsCollection.findOne({ relatedId: eventId })

      if (notification && notification.userEmail) {
        console.log("Found notification for user:", notification.userEmail)

        // Get the most recent event for this user
        const userEvents = await aeventsCollection
          .find({ userEmail: notification.userEmail })
          .sort({ _id: -1 })
          .limit(1)
          .toArray()

        if (userEvents.length > 0) {
          event = userEvents[0]
          console.log("Found most recent event for user:", event.eventName)
        }
      }
    }

    if (event) {
      console.log("Event found:", event)
      res.json({ success: true, event })
    } else {
      // If all attempts fail, dump some debug info
      const sampleEvents = await aeventsCollection.find({}).limit(3).toArray()
      console.log(
        "Sample events in database:",
        sampleEvents.map((e) => ({ id: e._id.toString(), name: e.eventName })),
      )

      res.status(404).json({
        success: false,
        message: "Event not found",
        debug: {
          requestedId: eventId,
          sampleEvents: sampleEvents.map((e) => ({ id: e._id.toString(), name: e.eventName })),
        },
      })
    }
  } catch (error) {
    console.error("Error fetching event details:", error)
    res.status(500).json({
      success: false,
      message: "Server error while fetching event details",
      error: error.message,
    })
  }
})

// Update the notifications endpoint to include more detailed logging
app.get("/api/notifications", async (req, res) => {
  try {
    // Check if user is authenticated
    if (!req.session || !req.session.user || !req.session.user.email) {
      return res.status(401).json({
        success: false,
        error: "Not authenticated",
      })
    }

    const userEmail = req.session.user.email
    console.log("Fetching notifications for user:", userEmail)

    const db = await connectToDatabase()
    const notificationsCollection = db.collection("notifications")

    // Get notifications for the current user only
    const notifications = await notificationsCollection
      .find({
        userEmail: userEmail, // Filter by the current user's email
      })
      .sort({ timestamp: -1 })
      .toArray()

    console.log(`Found ${notifications.length} notifications for user ${userEmail}`)

    // Count unread notifications
    const unreadCount = notifications.filter((notification) => !notification.read).length
    console.log(`Unread notifications: ${unreadCount}`)

    res.json({
      success: true,
      notifications: notifications,
      unreadCount: unreadCount,
    })
  } catch (error) {
    console.error("Error fetching notifications:", error)
    res.status(500).json({
      success: false,
      error: "Failed to fetch notifications",
    })
  }
})

app.post("/api/updateNotificationAfterPayment", async (req, res) => {
  const { notificationId, eventId, eventName, eventDate, startTime, endTime } = req.body

  try {
    const db = await connectToDatabase()
    const notificationsCollection = db.collection("notifications")

    // Delete the payment notification
    await notificationsCollection.deleteOne({ _id: new ObjectId(notificationId) })

    // Create a new notification
    const newNotification = {
      userEmail: req.session.user.email,
      message: `Your payment for "${eventName}" has been processed successfully.`,
      subject: `${eventName} on ${eventDate} ${startTime}-${endTime}`,
      type: "payment_confirmed",
      relatedId: eventId,
      timestamp: new Date(),
      read: false,
    }

    await notificationsCollection.insertOne(newNotification)

    res.json({ success: true, message: "Notification updated successfully" })
  } catch (error) {
    console.error("Error updating notification:", error)
    res.status(500).json({ success: false, message: "Error updating notification", error: error.message })
  }
})

app.post("/api/markNotificationAsRead", async (req, res) => {
  try {
    // Check if user is authenticated
    if (!req.session || !req.session.user || !req.session.user.email) {
      return res.status(401).json({
        success: false,
        error: "Not authenticated",
      })
    }

    const { notificationId } = req.body

    if (!notificationId) {
      return res.status(400).json({
        success: false,
        error: "Notification ID is required",
      })
    }

    const db = await connectToDatabase()
    const notificationsCollection = db.collection("notifications")

    // Update the notification to mark it as read
    const result = await notificationsCollection.updateOne(
      {
        _id: new ObjectId(notificationId),
        userEmail: req.session.user.email, // Ensure we only update this user's notification
      },
      { $set: { read: true } },
    )

    res.json({
      success: true,
      message: "Notification marked as read",
      modifiedCount: result.modifiedCount,
    })
  } catch (error) {
    console.error("Error marking notification as read:", error)
    res.status(500).json({
      success: false,
      error: "Failed to mark notification as read",
    })
  }
})

app.post("/api/markAllNotificationsRead", async (req, res) => {
  try {
    // Check if user is authenticated
    if (!req.session || !req.session.user || !req.session.user.email) {
      return res.status(401).json({
        success: false,
        error: "Not authenticated",
      })
    }

    const userEmail = req.session.user.email

    const { notificationIds } = req.body

    if (!notificationIds || !Array.isArray(notificationIds) || notificationIds.length === 0) {
      return res.status(400).json({
        success: false,
        error: "No notification IDs provided",
      })
    }

    const db = await connectToDatabase()
    const notificationsCollection = db.collection("notifications")

    // Update selected notifications for this user to be marked as read
    const result = await notificationsCollection.updateMany(
      {
        _id: { $in: notificationIds.map((id) => new MongoClient.ObjectId(id)) },
        userEmail: userEmail, // Ensure we only update this user's notifications
      },
      { $set: { read: true } },
    )

    res.json({
      success: true,
      message: "Selected notifications marked as read",
      modifiedCount: result.modifiedCount,
    })
  } catch (error) {
    console.error("Error marking selected notifications as read:", error)
    res.status(500).json({
      success: false,
      error: "Failed to mark selected notifications as read",
    })
  }
})

// Declare notifications and showEventDetails variables
const notifications = []
const showEventDetails = () => {}

function updateNotificationList() {
  const notificationList = document.getElementById("notificationList")
  if (!notificationList) {
    console.error("Notification list element not found")
    return
  }

  notificationList.innerHTML = "" // Clear existing list

  if (!notifications || notifications.length === 0) {
    const noNotifications = document.createElement("div")
    noNotifications.classList.add("no-notifications")
    noNotifications.textContent = "No new notifications"
    notificationList.appendChild(noNotifications)
    return
  }

  notifications.forEach((notification) => {
    // Skip deleted event notifications
    if (notification.type === "event_deleted") {
      return
    }

    const notificationItem = document.createElement("div")
    notificationItem.classList.add("notification-item")
    notificationItem.dataset.id = notification._id

    // Create checkbox
    const checkbox = document.createElement("input")
    checkbox.type = "checkbox"
    checkbox.className = "notification-checkbox"
    checkbox.dataset.id = notification._id
    checkbox.onclick = (e) => e.stopPropagation() // Prevent opening modal when clicking checkbox

    // Create content wrapper
    const contentWrapper = document.createElement("div")
    contentWrapper.className = "notification-content"

    // Create subject line
    const subjectDiv = document.createElement("div")
    subjectDiv.className = "notification-subject"

    // Format the subject line based on notification data
    let subject = notification.subject || ""
    if (!subject && notification.message) {
      // Try to extract event name and date from message if subject is not available
      const eventNameMatch = notification.message.match(/"([^"]+)"/)
      const eventName = eventNameMatch ? eventNameMatch[1] : "Event"

      // Try to extract date from message or use a placeholder
      const dateMatch = notification.message.match(/(\d{4}-\d{2}-\d{2})/)
      const date = dateMatch ? dateMatch[1] : ""

      subject = `${eventName}${date ? " on " + date : ""}`
    }
    subjectDiv.textContent = subject

    // Create message element
    const messageDiv = document.createElement("div")
    messageDiv.className = "notification-message"
    messageDiv.textContent = notification.message

    // Create timestamp element
    const timestampDiv = document.createElement("div")
    timestampDiv.className = "notification-timestamp"
    timestampDiv.textContent = new Date(notification.timestamp).toLocaleString()

    // Add payment required indicator if needed
    if (notification.type === "payment_required") {
      const paymentRequiredDiv = document.createElement("div")
      paymentRequiredDiv.className = "payment-required"
      paymentRequiredDiv.textContent = "Payment Required"
      contentWrapper.appendChild(paymentRequiredDiv)
    }

    // Add subject, message and timestamp to content wrapper
    contentWrapper.appendChild(subjectDiv)
    contentWrapper.appendChild(messageDiv)
    contentWrapper.appendChild(timestampDiv)

    // Add elements to notification item
    notificationItem.appendChild(checkbox)
    notificationItem.appendChild(contentWrapper)

    // Add click event to show event details
    notificationItem.addEventListener("click", (e) => {
      if (e.target !== checkbox) {
        showEventDetails(notification)
      }
    })

    notificationList.appendChild(notificationItem)
  })
}

app.get("/api/calendar-events", async (req, res) => {
  try {
    const db = await connectToDatabase()
    const eventsCollection = db.collection("aevents") // or whichever collection stores your events

    const events = await eventsCollection.find({}).toArray()

    // Format the events if necessary
    const formattedEvents = events.map((event) => ({
      ...event,
      startTime: formatTime(event.startTime),
      endTime: formatTime(event.endTime),
    }))

    res.json(formattedEvents)
  } catch (error) {
    console.error("Error fetching calendar events:", error)
    res.status(500).json({ error: "Failed to fetch calendar events" })
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
app.post("/api/create-homeowner-account", async (req, res) => {
  try {
    const { username, email, password } = req.body

    if (!username || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "Username, email, and password are required",
      })
    }

    const db = await connectToDatabase()
    const usersCollection = db.collection("acc")

    // Check if user already exists
    const existingUser = await usersCollection.findOne({
      $or: [{ username }, { email }],
    })

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "Username or email already exists",
      })
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10)

    // Create new user
    const newUser = {
      username,
      email,
      password: hashedPassword,
      role: "homeowner",
      createdAt: new Date(),
    }

    await usersCollection.insertOne(newUser)

    res.status(201).json({
      success: true,
      message: "Account created successfully",
    })
  } catch (error) {
    console.error("Error creating homeowner account:", error)
    res.status(500).json({
      success: false,
      message: "Server error while creating account",
      error: error.message,
    })
  }
})

app.post("/api/create-homeowner", async (req, res) => {
  try {
    const {
      firstName,
      lastName,
      Address,
      email,
      phoneNumber,
      landLine,
      paymentStatus,
      homeownerStatus,
      carStickerStatus,
    } = req.body

    if (!firstName || !lastName || !Address || !email || !phoneNumber) {
      return res.status(400).json({
        success: false,
        message: "Missing required homeowner details",
      })
    }

    const db = await connectToDatabase()
    const homeownersCollection = db.collection("homeowners")

    // Check if homeowner already exists
    const existingHomeowner = await homeownersCollection.findOne({ email })

    if (existingHomeowner) {
      return res.status(400).json({
        success: false,
        message: "Homeowner with this email already exists",
      })
    }

    // Create new homeowner
    const newHomeowner = {
      firstName,
      lastName,
      Address,
      email,
      phoneNumber,
      landLine: landLine || "",
      paymentStatus: paymentStatus || "Compliant",
      homeownerStatus: homeownerStatus || "Compliant",
      carStickerStatus: carStickerStatus || "undetermined",
      createdAt: new Date(),
    }

    await homeownersCollection.insertOne(newHomeowner)

    // Log activity
    await logActivity("homeownerCreated", `New homeowner account created for ${firstName} ${lastName}`)

    res.status(201).json({
      success: true,
      message: "Homeowner details saved successfully",
    })
  } catch (error) {
    console.error("Error creating homeowner:", error)
    res.status(500).json({
      success: false,
      message: "Server error while saving homeowner details",
      error: error.message,
    })
  }
})

app.get("/api/generate-payment-report", async (req, res) => {
  try {
    const { type, range, format, startDate, endDate } = req.query

    const db = await connectToDatabase()
    const homeownersCollection = db.collection("homeowners")
    const paymentsCollection = db.collection("payments")

    // Get date range
    let dateFilter = {}
    const now = new Date()

    if (range === "this_month") {
      const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1)
      dateFilter = { createdAt: { $gte: startOfMonth } }
    } else if (range === "last_month") {
      const startOfLastMonth = new Date(now.getFullYear(), now.getMonth() - 1, 1)
      const endOfLastMonth = new Date(now.getFullYear(), now.getMonth(), 0)
      dateFilter = { createdAt: { $gte: startOfLastMonth, $lte: endOfLastMonth } }
    } else if (range === "last_quarter") {
      const startOfQuarter = new Date(now.getFullYear(), Math.floor(now.getMonth() / 3) * 3 - 3, 1)
      dateFilter = { createdAt: { $gte: startOfQuarter } }
    } else if (range === "last_year") {
      const startOfLastYear = new Date(now.getFullYear() - 1, 0, 1)
      const endOfLastYear = new Date(now.getFullYear(), 0, 0)
      dateFilter = { createdAt: { $gte: startOfLastYear, $lte: endOfLastYear } }
    } else if (range === "custom" && startDate && endDate) {
      const startDateObj = new Date(startDate)
      const endDateObj = new Date(endDate)
      endDateObj.setHours(23, 59, 59, 999) // Set to end of day
      dateFilter = { createdAt: { $gte: startDateObj, $lte: endDateObj } }
    }

    // Get data based on report type
    let reportData = []

    if (type === "payment_frequency") {
      // Get all homeowners with their payment status
      reportData = await homeownersCollection.find({}).toArray()

      // If date filter is applied, get payment history for the period
      if (Object.keys(dateFilter).length > 0) {
        const payments = await paymentsCollection.find(dateFilter).toArray()

        // Create a map of homeowner emails to payment counts
        const paymentCounts = {}
        payments.forEach((payment) => {
          if (!paymentCounts[payment.email]) {
            paymentCounts[payment.email] = 0
          }
          paymentCounts[payment.email]++
        })

        // Add payment frequency to homeowner data
        reportData = reportData.map((homeowner) => ({
          ...homeowner,
          paymentFrequency: paymentCounts[homeowner.email] || 0,
        }))
      }
    } else if (type === "delinquent_owners") {
      // Get only delinquent homeowners
      reportData = await homeownersCollection
        .find({
          $or: [{ paymentStatus: "Delinquent" }, { homeownerStatus: "Delinquent" }],
        })
        .toArray()
    } else if (type === "payment_history") {
      // Get payment history for all homeowners
      const payments = await paymentsCollection.find(dateFilter).toArray()

      // Group payments by homeowner
      const homeownerEmails = [...new Set(payments.map((payment) => payment.email))]

      // Get homeowner details
      const homeowners = await homeownersCollection
        .find({
          email: { $in: homeownerEmails },
        })
        .toArray()

      // Create a map of emails to homeowner details
      const homeownerMap = {}
      homeowners.forEach((homeowner) => {
        homeownerMap[homeowner.email] = homeowner
      })

      // Create report data with payment history
      reportData = payments.map((payment) => ({
        ...payment,
        firstName: homeownerMap[payment.email]?.firstName || "",
        lastName: homeownerMap[payment.email]?.lastName || "",
        Address: homeownerMap[payment.email]?.Address || "",
      }))
    }

    // Create Excel workbook
    const excel = officegen("xlsx")

    // Add worksheet
    const sheet = excel.makeNewSheet()
    sheet.name =
      type === "payment_frequency"
        ? "Payment Frequency"
        : type === "delinquent_owners"
          ? "Delinquent Owners"
          : "Payment History"

    // Add headers based on report type
    let headers = []

    if (type === "payment_frequency") {
      headers = [
        "Last Name",
        "First Name",
        "Address",
        "Phone Number",
        "Landline",
        "Payment Status",
        "Homeowner Status",
        "Car Sticker Status",
        "Payment Frequency",
      ]
    } else if (type === "delinquent_owners") {
      headers = [
        "Last Name",
        "First Name",
        "Address",
        "Phone Number",
        "Landline",
        "Payment Status",
        "Homeowner Status",
        "Car Sticker Status",
        "Last Payment Date",
      ]
    } else if (type === "payment_history") {
      headers = [
        "Last Name",
        "First Name",
        "Address",
        "Amount",
        "Payment Date",
        "Payment Method",
        "Reference Number",
        "Status",
      ]
    }

    sheet.data[0] = headers

    // Add data rows based on report type
    reportData.forEach((item, index) => {
      let rowData = []

      if (type === "payment_frequency") {
        rowData = [
          item.lastName || "",
          item.firstName || "",
          item.Address || "",
          item.phoneNumber || "",
          item.landLine || "",
          item.paymentStatus || "",
          item.homeownerStatus || "",
          item.carStickerStatus || "Undetermined",
          item.paymentFrequency || 0,
        ]
      } else if (type === "delinquent_owners") {
        rowData = [
          item.lastName || "",
          item.firstName || "",
          item.Address || "",
          item.phoneNumber || "",
          item.landLine || "",
          item.paymentStatus || "",
          item.homeownerStatus || "",
          item.carStickerStatus || "Undetermined",
          item.lastPaymentDate ? new Date(item.lastPaymentDate).toLocaleDateString() : "Never",
        ]
      } else if (type === "payment_history") {
        rowData = [
          item.lastName || "",
          item.firstName || "",
          item.Address || "",
          item.amount ? `₱${item.amount.toFixed(2)}` : "",
          item.paymentDate ? new Date(item.paymentDate).toLocaleDateString() : "",
          item.paymentMethod || "",
          item.referenceNumber || "",
          item.status || "",
        ]
      }

      sheet.data[index + 1] = rowData
    })

    // Set content type based on format
    if (format === "excel" || format === "xlsx") {
      res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
      res.setHeader("Content-Disposition", `attachment; filename=${type}-report.xlsx`)
    } else if (format === "csv") {
      res.setHeader("Content-Type", "text/csv")
      res.setHeader("Content-Disposition", `attachment; filename=${type}-report.csv`)
    } else if (format === "pdf") {
      res.setHeader("Content-Type", "application/pdf")
      res.setHeader("Content-Disposition", `attachment; filename=${type}-report.pdf`)
    } else {
      res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
      res.setHeader("Content-Disposition", `attachment; filename=${type}-report.xlsx`)
    }

    // Generate and send the file
    excel.generate(res)

    // Log activity
    await logActivity("reportGenerated", `Generated ${type} report in ${format} format`)
  } catch (error) {
    console.error("Error generating payment report:", error)
    res.status(500).json({
      success: false,
      message: "Failed to generate payment report",
      error: error.message,
    })
  }
})

async function notifyDelinquentHomeowners() {
  try {
    const db = await connectToDatabase()
    const homeownersCollection = db.collection("homeowners")
    const notificationsCollection = db.collection("notifications")

    // Find all homeowners with delinquent status
    const delinquentHomeowners = await homeownersCollection
      .find({
        $or: [{ paymentStatus: "Not Paid" }, { homeownerStatus: "Delinquent" }],
      })
      .toArray()

    console.log(`Found ${delinquentHomeowners.length} delinquent homeowners`)

    // Create notifications for each delinquent homeowner
    for (const homeowner of delinquentHomeowners) {
      // Check if we already sent a notification this month
      const today = new Date()
      const firstDayOfMonth = new Date(today.getFullYear(), today.getMonth(), 1)

      const existingNotification = await notificationsCollection.findOne({
        userEmail: homeowner.email,
        type: "payment_reminder",
        timestamp: { $gte: firstDayOfMonth },
      })

      // If no notification was sent this month, create one
      if (!existingNotification) {
        await createNotification(
          homeowner.email,
          "payment_reminder",
          `Payment Reminder: Your homeowner dues are currently marked as unpaid. Please settle your payment as soon as possible to avoid penalties.`,
          null,
          "Payment Reminder",
          null,
          { isPaid: false },
        )

        console.log(`Sent payment reminder to ${homeowner.email}`)
      }
    }

    return {
      success: true,
      message: `Notifications sent to ${delinquentHomeowners.length} delinquent homeowners`,
    }
  } catch (error) {
    console.error("Error sending delinquent notifications:", error)
    return {
      success: false,
      message: "Failed to send notifications",
      error: error.message,
    }
  }
}
schedule.scheduleJob("0 9 1 * *", async () => {
  console.log("Running scheduled delinquent homeowner notifications")
  await notifyDelinquentHomeowners()
})

app.post("/api/send-delinquent-notifications", async (req, res) => {
  try {
    const { type, subject, message, recipientType } = req.body

    if (!subject || !message) {
      return res.status(400).json({
        success: false,
        message: "Subject and message are required",
      })
    }

    // Assuming you have a function to connect to the database
    // const db = await connectToDatabase(); // Uncomment and adjust if needed
    const db = await connectToDatabase()
    const homeownersCollection = db.collection("homeowners")
    const notificationsCollection = db.collection("notifications")

    // Determine which homeowners to notify based on recipientType
    let query = {}

    if (recipientType === "delinquent") {
      query = { paymentStatus: "Delinquent" }
    } else if (recipientType === "not_paid") {
      query = { paymentStatus: "Not Paid" }
    } else if (recipientType === "all_delinquent") {
      query = {
        $or: [{ paymentStatus: "Delinquent" }, { paymentStatus: "Not Paid" }],
      }
    } else {
      // Default to all delinquent homeowners
      query = {
        $or: [{ paymentStatus: "Delinquent" }, { paymentStatus: "Not Paid" }],
      }
    }

    // Find all homeowners matching the query
    const homeowners = await homeownersCollection.find(query).toArray()

    if (homeowners.length === 0) {
      return res.status(404).json({
        success: false,
        message: "No homeowners found matching the criteria",
      })
    }

    // Create notifications for each homeowner
    const notifications = []

    for (const homeowner of homeowners) {
      if (homeowner.email) {
        notifications.push({
          userEmail: homeowner.email,
          type: type || "payment_reminder",
          subject,
          message,
          timestamp: new Date(),
          read: false,
        })
      }
    }

    // Insert all notifications
    if (notifications.length > 0) {
      await notificationsCollection.insertMany(notifications)
    }

    // Record this notification sending in sent_notifications collection
    await db.collection("sent_notifications").insertOne({
      type: type || "payment_reminder",
      subject,
      message,
      recipientType,
      recipientCount: notifications.length,
      timestamp: new Date(),
    })

    // Log the activity
    // Assuming you have a function to log activity
    // await logActivity(
    //   "notificationSent",
    //   `Sent ${subject} notification to ${notifications.length} homeowners`
    // ); // Uncomment and adjust if needed
    await logActivity("notificationSent", `Sent ${subject} notification to ${notifications.length} homeowners`)

    res.json({
      success: true,
      message: `Notifications sent successfully to ${notifications.length} homeowners`,
      recipientCount: notifications.length,
    })
  } catch (error) {
    console.error("Error sending notifications:", error)
    res.status(500).json({
      success: false,
      message: "Failed to send notifications",
      error: error.message,
    })
  }
})

// API endpoint to manually trigger notifications
app.post("/api/notify-delinquent-homeowners", async (req, res) => {
  try {
    const result = await notifyDelinquentHomeowners()
    res.json(result)
  } catch (error) {
    console.error("Error in notify-delinquent-homeowners endpoint:", error)
    res.status(500).json({
      success: false,
      message: "Server error while sending notifications",
      error: error.message,
    })
  }
})

app.get("/api/payment-report", async (req, res) => {
  try {
    const db = await connectToDatabase()
    const homeownersCollection = db.collection("homeowners")

    // Get all homeowners
    const homeowners = await homeownersCollection.find({}).toArray()

    // Count payment statuses
    const paymentStats = {
      paid: homeowners.filter((h) => h.paymentStatus === "Paid").length,
      notPaid: homeowners.filter((h) => h.paymentStatus === "Not Paid").length,
      toBeVerified: homeowners.filter((h) => h.paymentStatus === "To be verified").length,
      total: homeowners.length,
    }

    res.json({
      success: true,
      stats: paymentStats,
      homeowners: homeowners,
    })
  } catch (error) {
    console.error("Error generating payment report:", error)
    res.status(500).json({
      success: false,
      message: "Failed to generate payment report",
      error: error.message,
    })
  }
})

app.post("/api/homeowners/generate-account", async (req, res) => {
  try {
    const { firstName, lastName, address, phoneNumber, landLine, paymentStatus, carStickerStatus } = req.body

    if (!firstName || !lastName || !address || !phoneNumber) {
      return res.status(400).json({
        success: false,
        error: "Missing required fields",
      })
    }

    const db = await connectToDatabase()
    const homeownersCollection = db.collection("homeowners")
    const accCollection = db.collection("acc")

    // Generate username and email
    const username =
      (firstName.charAt(0) + lastName).toLowerCase().replace(/\s+/g, "") + Math.floor(100 + Math.random() * 900)
    const email = username + "@example.com"

    // Extract block and lot numbers from address
    const blockMatch = address.match(/Block\s+(\d+)/i)
    const lotMatch = address.match(/Lot\s+(\d+)/i)

    if (!blockMatch || !lotMatch) {
      return res.status(400).json({
        success: false,
        error: "Address must contain valid Block and Lot numbers",
      })
    }

    const blockNumber = blockMatch[1]
    const lotNumber = lotMatch[1]
    const currentYear = new Date().getFullYear()

    // Generate password in the format: ASC + block + lot + year + !
    const password = `ASC${blockNumber}${lotNumber}${currentYear}!`

    // Check if username or email already exists
    const existingUser = await accCollection.findOne({
      $or: [{ username }, { email }],
    })

    if (existingUser) {
      return res.status(400).json({
        success: false,
        error: "Username or email already exists. Please try again.",
      })
    }

    // Create account in acc collection
    const hashedPassword = await bcrypt.hash(password, 10)
    await accCollection.insertOne({
      username,
      email,
      password: hashedPassword,
      role: "homeowner",
      createdAt: new Date(),
    })

    // Create homeowner record
    const homeowner = {
      firstName,
      lastName,
      Address: address,
      email,
      phoneNumber,
      landLine: landLine || "",
      paymentStatus: paymentStatus || "Compliant",
      homeownerStatus: paymentStatus === "Delinquent" ? "Delinquent" : "Compliant",
      carStickerStatus: carStickerStatus || "undetermined",
      createdAt: new Date(),
    }

    await homeownersCollection.insertOne(homeowner)

    // Log activity
    await logActivity("accountGenerated", `Generated account for homeowner ${firstName} ${lastName}`)

    res.json({
      success: true,
      message: "Account generated successfully",
      account: {
        username,
        password,
      },
    })
  } catch (error) {
    console.error("Error generating homeowner account:", error)
    res.status(500).json({
      success: false,
      error: "Server error while generating account",
    })
  }
})

app.get("/api/generate-payment-report", async (req, res) => {
  try {
    const { type, range, format, startDate, endDate } = req.query

    const db = await connectToDatabase()
    const homeownersCollection = db.collection("homeowners")

    // Get date range
    let dateFilter = new Date()
    if (range === "last-month") {
      dateFilter.setMonth(dateFilter.getMonth() - 1)
    } else if (range === "last-quarter") {
      dateFilter.setMonth(dateFilter.getMonth() - 3)
    } else if (range === "last-year") {
      dateFilter.setFullYear(dateFilter.getFullYear() - 1)
    } else if (range === "custom" && startDate && endDate) {
      dateFilter = new Date(startDate)
    }

    // Get homeowners data
    const homeowners = await homeownersCollection.find({}).toArray()

    // Create Excel workbook
    const excel = officegen("xlsx")

    // Add worksheet
    const sheet = excel.makeNewSheet()
    sheet.name = "Homeowner Payments"

    // Add headers
    const headers = [
      "Last Name",
      "First Name",
      "Address",
      "Phone Number",
      "Landline",
      "Payment Status",
      "Homeowner Status",
    ]
    sheet.data[0] = headers

    // Add data rows
    homeowners.forEach((homeowner, index) => {
      sheet.data[index + 1] = [
        homeowner.lastName || "",
        homeowner.firstName || "",
        homeowner.Address || "",
        homeowner.phoneNumber || "",
        homeowner.landLine || "",
        homeowner.paymentStatus || "",
        homeowner.homeownerStatus || "",
      ]
    })

    // Set content type based on format
    if (format === "excel" || format === "xlsx") {
      res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
      res.setHeader("Content-Disposition", "attachment; filename=homeowner-payments.xlsx")
    } else if (format === "csv") {
      res.setHeader("Content-Type", "text/csv")
      res.setHeader("Content-Disposition", "attachment; filename=homeowner-payments.csv")
    } else {
      res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
      res.setHeader("Content-Disposition", "attachment; filename=homeowner-payments.xlsx")
    }

    // Generate and send the file
    excel.generate(res)
  } catch (error) {
    console.error("Error generating payment report:", error)
    res.status(500).json({
      success: false,
      message: "Failed to generate payment report",
      error: error.message,
    })
  }
})

app.get("/api/generate-payment-report", async (req, res) => {
  try {
    const { type, range, format, startDate, endDate } = req.query

    const db = await connectToDatabase()
    const homeownersCollection = db.collection("homeowners")

    // Get date range
    let dateFilter = new Date()
    if (range === "last-month") {
      dateFilter.setMonth(dateFilter.getMonth() - 1)
    } else if (range === "last-quarter") {
      dateFilter.setMonth(dateFilter.getMonth() - 3)
    } else if (range === "last-year") {
      dateFilter.setFullYear(dateFilter.getFullYear() - 1)
    } else if (range === "custom" && startDate && endDate) {
      dateFilter = new Date(startDate)
    }

    // Get homeowners data
    const homeowners = await homeownersCollection.find({}).toArray()

    // Create Excel workbook
    const excel = officegen("xlsx")

    // Add worksheet
    const sheet = excel.makeNewSheet()
    sheet.name = "Homeowner Payments"

    // Add headers
    const headers = [
      "Last Name",
      "First Name",
      "Address",
      "Phone Number",
      "Landline",
      "Payment Status",
      "Homeowner Status",
      "Car Sticker Status",
    ]
    sheet.data[0] = headers

    // Add data rows
    homeowners.forEach((homeowner, index) => {
      sheet.data[index + 1] = [
        homeowner.lastName || "",
        homeowner.firstName || "",
        homeowner.Address || "",
        homeowner.phoneNumber || "",
        homeowner.landLine || "",
        homeowner.paymentStatus || "",
        homeowner.homeownerStatus || "",
        homeowner.carStickerStatus || "Undetermined",
      ]
    })

    // Set content type based on format
    if (format === "excel" || format === "xlsx") {
      res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
      res.setHeader("Content-Disposition", "attachment; filename=homeowner-payments.xlsx")
    } else if (format === "csv") {
      res.setHeader("Content-Type", "text/csv")
      res.setHeader("Content-Disposition", "attachment; filename=homeowner-payments.csv")
    } else {
      res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
      res.setHeader("Content-Disposition", "attachment; filename=homeowner-payments.xlsx")
    }

    // Generate and send the file
    excel.generate(res)
  } catch (error) {
    console.error("Error generating payment report:", error)
    res.status(500).json({
      success: false,
      message: "Failed to generate payment report",
      error: error.message,
    })
  }
})

// CONCERN REPLY-----------------------------------------------

// Handle form submission

app.post("/sendReply", upload.single("attachment"), async (req, res) => {
  const { subject, message, concernId } = req.body

  const attachment = req.file ? req.file.filename : null

  // Validate inputs
  if (!subject || !message || !concernId) {
    return res.status(400).json({ success: false, message: "Subject, message, and concernId are required" })
  }

  try {
    const db = await connectToDatabase()
    const concernsCollection = db.collection("Concerns")

    // Get the concern to find the user's email
    const concern = await concernsCollection.findOne({ _id: new ObjectId(concernId) })

    if (!concern) {
      return res.status(404).json({ success: false, message: "Concern not found" })
    }

    // Update the concern document with the reply
    await concernsCollection.updateOne(
      { _id: new ObjectId(concernId) },
      {
        $push: { replies: { reply: message, attachment, timestamp: new Date() } },
        $set: { status: "replied" }, // Set status to 'replied'
      },
    )

    // Create a notification for the homeowner
    if (concern.email) {
      await createNotification(concern.email, "admin_reply", message, concernId, subject, null, {
        isAdminResponse: true,
      })
    }

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

app.get("/GenerateUPW", async (req, res) => {
  try {
    const db = await connectToDatabase()
    const homeownersCollection = db.collection("homeowners")

    //Apply logic here
  } catch (error) {
    console.error("Error fetching event types:", error)

    res.status(500).json({ error: "Failed to fetch event types" })
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

// Add this after other middleware and before routes

app.use("/api", (req, res, next) => {
  res.setHeader("Content-Type", "application/json")

  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate")

  res.setHeader("Pragma", "no-cache")

  next()
})

app.options("*", cors())

app.use(express.json())

app.use(express.urlencoded({ extended: true }))

app.use(bodyParser.json())

// Add these endpoints for monthly payments management
// Place this code in an appropriate location in your server.js file

// Endpoint to get monthly payments with filtering
app.get("/api/monthly-payments", async (req, res) => {
  try {
    const { status, search, page = 1, limit = 10 } = req.query
    const skip = (page - 1) * limit

    const db = await connectToDatabase()
    const monthlyPaymentsCollection = db.collection("monthlyDuesPayments")

    // Build query based on filters
    const query = {}

    if (status && status !== "all") {
      query.status = status
    }

    if (search) {
      query.$or = [{ userEmail: { $regex: search, $options: "i" } }, { userName: { $regex: search, $options: "i" } }]
    }

    // Get total count for pagination
    const totalPayments = await monthlyPaymentsCollection.countDocuments(query)

    // Get payments with pagination
    const payments = await monthlyPaymentsCollection
      .find(query)
      .sort({ submittedAt: -1 })
      .skip(skip)
      .limit(Number.parseInt(limit))
      .toArray()

    res.json({
      success: true,
      payments,
      currentPage: Number.parseInt(page),
      totalPages: Math.ceil(totalPayments / limit) || 1,
      totalPayments,
    })
  } catch (error) {
    console.error("Error fetching monthly payments:", error)
    res.status(500).json({
      success: false,
      message: "Error fetching payments",
      error: error.message,
    })
  }
})

// Endpoint to approve a payment
app.post("/api/monthly-payments/:id/approve", async (req, res) => {
  try {
    const { id } = req.params
    const db = await connectToDatabase()
    const monthlyPaymentsCollection = db.collection("monthlyDuesPayments")
    const homeownersCollection = db.collection("homeowners")

    // Find the payment
    const payment = await monthlyPaymentsCollection.findOne({ _id: new ObjectId(id) })

    if (!payment) {
      return res.status(404).json({
        success: false,
        message: "Payment not found",
      })
    }

    // Update payment status
    await monthlyPaymentsCollection.updateOne(
      { _id: new ObjectId(id) },
      {
        $set: {
          status: "approved",
          approvedAt: new Date(),
          approvedBy: req.session.user ? req.session.user.email : "admin",
        },
      },
    )

    // Update homeowner status
    if (payment.userEmail) {
      await homeownersCollection.updateOne(
        { email: payment.userEmail },
        {
          $set: {
            paymentStatus: "Compliant",
            homeownerStatus: "Compliant",
            lastPaymentDate: new Date(),
          },
        },
      )
    }

    // Log the activity
    await logActivity("paymentApproval", `Monthly dues payment for ${payment.userEmail || payment.userName} approved`)

    // Create notification for the user
    if (payment.userEmail) {
      await createNotification(
        payment.userEmail,
        "payment_approved",
        "Your monthly dues payment has been approved. Your account is now active.",
        payment._id.toString(),
      )
    }

    res.json({
      success: true,
      message: "Payment approved successfully",
    })
  } catch (error) {
    console.error("Error approving payment:", error)
    res.status(500).json({
      success: false,
      message: "Error approving payment",
      error: error.message,
    })
  }
})

// Endpoint to reject a payment
app.post("/api/monthly-payments/:id/reject", async (req, res) => {
  try {
    const { id } = req.params
    const { reason } = req.body

    if (!reason) {
      return res.status(400).json({
        success: false,
        message: "Rejection reason is required",
      })
    }

    const db = await connectToDatabase()
    const monthlyPaymentsCollection = db.collection("monthlyDuesPayments")

    // Find the payment
    const payment = await monthlyPaymentsCollection.findOne({ _id: new ObjectId(id) })

    if (!payment) {
      return res.status(404).json({
        success: false,
        message: "Payment not found",
      })
    }

    // Update payment status
    await monthlyPaymentsCollection.updateOne(
      { _id: new ObjectId(id) },
      {
        $set: {
          status: "rejected",
          rejectedAt: new Date(),
          rejectedBy: req.session.user ? req.session.user.email : "admin",
          rejectionReason: reason,
        },
      },
    )

    // Log the rejection
    await logActivity(
      "paymentRejection",
      `Monthly dues payment for ${payment.userEmail || payment.userName} rejected: ${reason}`,
    )

    // Create notification for the user
    if (payment.userEmail) {
      await createNotification(
        payment.userEmail,
        "payment_rejected",
        `Your monthly dues payment was rejected. Reason: ${reason}`,
        payment._id.toString(),
      )
    }

    res.json({
      success: true,
      message: "Payment rejected successfully",
    })
  } catch (error) {
    console.error("Error rejecting payment:", error)
    res.status(500).json({
      success: false,
      message: "Error rejecting payment",
      error: error.message,
    })
  }
})

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

// Update the error handling middleware

/* app.use((err, req, res, next) => {

  console.error("Unhandled error:", err)

  res.status(500).json({

    success: false,

    message: "An unexpected error occurred",

    error: process.env.NODE_ENV === "production" ? "Internal server error" : err.message,

    timestamp: new Date().toISOString(),

  })

}) */

// Error handling middleware

app.use((err, req, res, next) => {
  console.error("Unhandled error:", err)

  res.status(500).json({
    success: false,

    message: "An unexpected error occurred",

    error: process.env.NODE_ENV === "production" ? "Internal server error" : err.message,
  })
})

module.exports = app

app.use((req, res, next) => {
  const oldJson = res.json

  res.json = (data) => {
    console.log("Response data:", JSON.stringify(data))

    oldJson.apply(res, [data]) // Fix: Pass data as an array
  }

  next()
})

// === Static File Serving (place this at the end of the file) ===

// Make sure this comes AFTER all API routes

const staticMiddleware = express.static(path.join(__dirname))

// Custom middleware to handle API requests before serving static files

app.use((req, res, next) => {
  // If it's an API request or specifically wants JSON, skip static serving

  if (req.path.startsWith("/api") || req.headers.accept?.includes("application/json")) {
    return next()
  }

  return staticMiddleware(req, res, next)
})
// Add this endpoint to check authentication status
app.get("/api/auth-status", (req, res) => {
  if (req.session && req.session.user) {
    res.json({
      authenticated: true,
      user: {
        username: req.session.user.username,
        email: req.session.user.email,
        role: req.session.user.role,
      },
    })
  } else {
    res.json({
      authenticated: false,
    })
  }
})

// Add this endpoint to serve static files with authentication check
app.get("/admin/*", (req, res, next) => {
  if (req.session && req.session.user && req.session.user.role === "admin") {
    next() // Allow access to admin pages
  } else {
    res.redirect("/login.html") // Redirect to login if not authenticated as admin
  }
})

// Serve static files AFTER API routes

app.use(express.static(path.join(__dirname)))

app.use("/images", express.static(path.join(__dirname, "images")))

app.use("/CSS", express.static(path.join(__dirname, "CSS")))

app.use("/Webpages", express.static(path.join(__dirname, "Webpages")))

// This should be the very last route

app.get("*", (req, res) => {
  // Check if the request wants JSON

  if (req.headers.accept?.includes("application/json")) {
    return res.status(404).json({ success: false, message: "API endpoint not found" })
  }

  res.sendFile(path.join(__dirname, "Webpages", "login.html"))
})

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

// Fix: Declare db outside the scope of the try block
let db

async function connectToDatabase() {
  try {
    const client = new MongoClient(uri, {
      serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
      },
    })

    await client.connect()
    console.log("Connected successfully to server")
    db = client.db(dbName) // Assign the database connection to the 'db' variable
    return db
  } catch (error) {
    console.error("Error connecting to database:", error)
    throw error // Re-throw the error to be handled by the calling function
  }
}

app.use((req, res, next) => {
  const oldJson = res.json

  res.json = (data) => {
    console.log("Response data:", JSON.stringify(data))

    const dataToSend = Array.isArray(data) ? data : [data]
    oldJson.apply(res, dataToSend)
  }

  next()
})

console.log("Fixed login route and middleware for delinquent users")
