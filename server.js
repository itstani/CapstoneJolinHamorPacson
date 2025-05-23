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
const mongoose = require("mongoose")
const generatePaymentReport = require('./generate-payment-report');
const { MemoryStore } = require('express-session')

const app = express()
const port = process.env.PORT || 3000
const dbName = process.env.DB_NAME || "avidadb"
const uri = process.env.MONGODB_URI

// Configure middleware
app.use(express.json())
app.use(bodyParser.urlencoded({ extended: true }))

// Configure CORS
app.use(cors({
  origin: [
    "https://avidasetting.onrender.com",
    "https://capstone-jolin-hamor-pacson.vercel.app"
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));


app.use((req, res, next) => {
  console.log("Request for:", req.path);
  next();
});

// Configure session with proper settings for persistence
app.use(session({
  secret: process.env.SESSION_SECRET || "N3$Pxm/mXm1eYY",
  resave: true,
  saveUninitialized: false,
  store: new MemoryStore({
    checkPeriod: 86400000 
  }),
  cookie: {
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    httpOnly: true,
    domain: process.env.NODE_ENV === "production" ? ".onrender.com" : undefined,
    path: "/"
  },
  proxy: true,
  rolling: true // Resets the cookie expiration on every response
}));

// Add trust proxy for secure cookies in production
if (process.env.NODE_ENV === "production") {
  app.set("trust proxy", 1);
}

// Replace the middleware registration in your server.js with this:

// Import the auth middleware
const protectAdminRoutes = require("./auth-middleware")



// Use the middleware to protect admin routes
app.use(protectAdminRoutes)


app.use(protectAdminRoutes);

module.exports = protectAdminRoutes

// Debug logging middleware
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`)
  console.log("Request Headers:", req.headers)
  console.log("Session:", req.session)
  next()
})

// API response middleware
app.use((req, res, next) => {
  if (req.path.startsWith("/api")) {
    res.setHeader("Content-Type", "application/json")
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private")
    res.setHeader("Pragma", "no-cache")
  }
  next()
})

app.use((req, res, next) => {
  // List of paths that should be accessible even for delinquent users
  const publicPaths = [
    "/login.html",
    "/MDPayment.html",
    "/monthly-payments.html",
    "Webpages/homeowner-dashboard.html",
    "/Webpages/monthly-payments.html",
    "/Webpages/Monthly-payments.html",
    "/api/monthly-dues-payment",
    "/api/submit-monthly-payment",
    "/images/",
    "/CSS/",
  ]

  // Check if the current path should be allowed without authentication
  const isPublicPath = publicPaths.some((path) => {
    const result = req.path === path || req.path.startsWith(path)
    if (result) console.log(`[DEBUG] Path ${req.path} matched public path ${path}`)
    return result
  })

  if (isPublicPath) {
    console.log(`[DEBUG] Public path accessed: ${req.path}`)
    return next()
  }

  next()
})

app.use((req, res, next) => {
  console.log("Session middleware - Current session:", {
    id: req.sessionID,
    user: req.session?.user,
    cookie: req.session?.cookie,
  })

  // Add a header to help debug authentication issues
  if (req.session && req.session.user) {
    res.setHeader("X-Auth-Status", "authenticated")
    res.setHeader("X-Auth-User", req.session.user.username || "unknown")
    res.setHeader("X-Auth-Role", req.session.user.role || "unknown")
  } else {
    res.setHeader("X-Auth-Status", "unauthenticated")
  }

  next()
})

// Add debug logging middleware right after session middleware
app.use((req, res, next) => {
  console.log("=== Session Debug Info ===");
  console.log("Request path:", req.path);
  console.log("Session ID:", req.sessionID);
  console.log("Session exists:", !!req.session);
  console.log("User in session:", req.session?.user);
  console.log("Cookies:", req.headers.cookie);
  console.log("Origin:", req.headers.origin);
  console.log("Referer:", req.headers.referer);
  console.log("========================");
  next();
});

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
    "/monthly-payments.html",
    "Webpages/homeowner-dashboard.html",
    "/Webpages/monthly-payments.html", // lowercase m
    "/Webpages/Monthly-payments.html", // uppercase M
    "/api/monthly-dues-payment",
    "/api/submit-monthly-payment",
    "/images/",
    "/CSS/",
  ]

  // Check if the current path is public (always allowed)
  const isPublicPath = publicPaths.some((path) => {
    const result = req.path === path || req.path.startsWith(path)
    if (result) console.log(`[DEBUG] Path ${req.path} matched public path ${path}`)
    return result
  })

  if (isPublicPath) {
    console.log(`[DEBUG] Allowing access to public path: ${req.path}`)
    return next() // Allow access to public paths
  }

  // Check if the current path is protected
  const isProtected = protectedPaths.some((path) => {
    const result = req.path === path || req.path.startsWith(path)
    if (result) console.log(`[DEBUG] Path ${req.path} matched protected path ${path}`)
    return result
  })

  if (isProtected) {
    // If this is a protected path and user is not logged in, redirect to login
    if (!req.session || !req.session.user) {
      console.log(`[DEBUG] Unauthorized access attempt to ${req.path}, redirecting to login`)
      return res.redirect("/login.html") // Redirect to login page
    }
  }

  next() // Proceed to the next middleware or route handler
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


// Helper function to convert time to 24-hour format string (HH:MM)
function convertTo24HourFormat(timeStr) {
    if (!timeStr || typeof timeStr !== 'string') return "00:00"; // Default or error
    const [time, modifier] = timeStr.toUpperCase().split(' ');
    if (!time || !modifier) return "00:00"; // Invalid format

    let [hours, minutes] = time.split(':');
    hours = parseInt(hours, 10);
    minutes = parseInt(minutes, 10);

    if (isNaN(hours) || isNaN(minutes)) return "00:00"; // Invalid numbers

    if (modifier === 'PM' && hours < 12) {
        hours += 12;
    } else if (modifier === 'AM' && hours === 12) { // Midnight case for 12 AM
        hours = 0;
    } else if (modifier === 'PM' && hours === 12) { // Noon case for 12 PM
        // hours remains 12, no change needed
    }


    return `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}`;
}

// Helper function to convert 24-hour "HH:MM" to "H:MM AM/PM"
function convert24HourTo12HourFormat(time24) {
    if (!time24 || typeof time24 !== 'string' || !time24.includes(':')) return 'N/A';
    const [hoursStr, minutesStr] = time24.split(':');
    const hours = parseInt(hoursStr, 10);
    const minutes = String(minutesStr).padStart(2, '0');
    const period = hours >= 12 ? 'PM' : 'AM';
    const adjustedHour = hours % 12 || 12; // Converts '00' or '12' to 12, others to hour % 12
    return `${adjustedHour}:${minutes} ${period}`;
}

// API endpoint to check authentication status
app.get("/api/auth-status", (req, res) => {
  if (req.session && req.session.user) {
    return res.json({
      authenticated: true,
      user: req.session.user,
    });
  } else {
    return res.json({ authenticated: false });
  }
});

app.get(
  ["/monthly-payments.html", "/Webpages/monthly-payments.html", "/Webpages/Monthly-payments.html"],
  (req, res) => {
    console.log(`[DEBUG] Special monthly payments route accessed: ${req.path}`)

    // Check if user is authenticated as admin
    if (req.session && req.session.user && req.session.user.role === "admin") {
      console.log("[DEBUG] Admin user accessing monthly payments page")
      res.sendFile(path.join(__dirname, "Webpages", "monthly-payments.html"))
    } else {
      console.log("[DEBUG] Non-admin user attempting to access monthly payments page")
      res.redirect("/login.html")
    }
  },
)
// Import the middleware


// Add a debug endpoint to check file existence
app.get("/api/debug/file-check", (req, res) => {
  const filesToCheck = [
    { path: "/monthly-payments.html", fullPath: path.join(__dirname, "monthly-payments.html") },
    { path: "/Webpages/monthly-payments.html", fullPath: path.join(__dirname, "Webpages", "monthly-payments.html") },
    { path: "/Webpages/Monthly-payments.html", fullPath: path.join(__dirname, "Webpages", "Monthly-payments.html") },
  ]

  const results = filesToCheck.map((file) => {
    const exists = fs.existsSync(file.fullPath)
    return {
      path: file.path,
      fullPath: file.fullPath,
      exists: exists,
    }
  })

  res.json({
    success: true,
    results: results,
    serverDirectory: __dirname,
  })
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
      username: req.body.username, // Include username in the payment data
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
          username: event.username,
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

app.post("/api/login", async (req, res) => {
  const { login, password } = req.body;
  
  try {
    console.log(`Login attempt for: ${login}`);

    const db = await connectToDatabase();
    const usersCollection = db.collection("acc");
    const homeownersCollection = db.collection("homeowners");
    const addressCollection = db.collection("address");

    if (!login || !password) {
      return res.status(400).json({
        success: false,
        message: "Username/email and password are required",
      });
    }

    // Find user by email or username
    const user = await usersCollection.findOne({
      $or: [

        { username: { $regex: new RegExp(`^${login}$`, "i") } },
      ],
    });

    if (!user) {
      console.log(`User not found: ${login}`);
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      console.log(`Invalid password for user: ${login}`);
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    // Only check homeowner delinquency if not admin
    if (user.role !== "admin") {
      const addresses = await addressCollection.find({}).toArray();

      // Try to find homeowner by username or email
      const homeowner = await homeownersCollection.findOne({
        $or: [
          { username: user.username },
        ]
      });

      if (!homeowner) {
        console.log("No matching homeowner found.");
        return res.status(404).json({
          success: false,
          message: "Homeowner record not found"
        });
      }

      // Match address
      const matchAddress = addresses.find(addr => {
        const hBlock = String(homeowner.Address?.Block?.$numberInt || homeowner.Address?.Block || "");
        const hLot = String(homeowner.Address?.Lot?.$numberInt || homeowner.Address?.Lot || "");
        const hPhase = String(homeowner.Address?.Phase?.$numberInt || homeowner.Address?.Phase || "");

        const aBlock = String(addr.Block?.$numberInt || addr.Block || "");
        const aLot = String(addr.Lot?.$numberInt || addr.Lot || "");
        const aPhase = String(addr.Phase?.$numberInt || addr.Phase || "");

        const match = hBlock === aBlock && hLot === aLot && hPhase === aPhase;
        if (match) {
          console.log(`✅ Match found: Block ${aBlock}, Lot ${aLot}, Phase ${aPhase}, Amount: ${addr.MDAmount}`);
        }
        return match;
      });

      const dueAmount = parseFloat(matchAddress?.MDAmount?.$numberDouble || matchAddress?.MDAmount || "1500.00");

      // Check for delinquent or almost due status (case-insensitive)
      const pStatus = (homeowner.PStatus || "").toLowerCase();

      console.log(`PStatus for ${user.username}: ${pStatus}`);

      if (pStatus === "delinquent") {
        console.log(`User ${user.username} is delinquent.`);
        // Calculate overdue days and penalty
        const lastPaymentDate = new Date(homeowner.lastPaymentDate);
        const today = new Date();
        const daysOverdue = Math.floor((today - lastPaymentDate) / (1000 * 60 * 60 * 24));
        const penalty = daysOverdue > 0 ? daysOverdue * 10 : 0;

        return res.json({
          success: false,
          isDelinquent: true,
          username: user.username,
          email: user.email || user.username,
          dueAmount: dueAmount + penalty,
          message: "Account is delinquent. Please pay your monthly dues.",
        });
      } else if (pStatus === "Almost Due") {
        return res.json({
          success: true,
          isAlmostDue: true,
          username: user.username,
          email: user.email || user.username,
          dueAmount: dueAmount,
          message: "Your dues are almost due. Would you like to pay now?",
        });
      }
    }


    // ✅ Login success — create session
    req.session.regenerate(async function (err) {
      if (err) {
        console.error("Error regenerating session:", err);
        return res.status(500).json({
          success: false,
          message: "Error creating session",
        });
      }

      req.session.user = {
        username: user.username,
        email: user.email || null,
        role: user.role || "homeowner",
        isDelinquent: user.isDelinquent || false
      };

      console.log("✅ Session set during login:", req.session);

      req.session.save(async (err) => {
        if (err) {
          console.error("Error saving session:", err);
          return res.status(500).json({
            success: false,
            message: "Error saving session",
          });
        }

        await logActivity("login", `User ${user.username} logged in successfully`);

        res.json({
          success: true,
          username: user.username,
          email: user.email || null,
          role: user.role || "homeowner",
          isDelinquent: user.isDelinquent || false,
          redirectUrl: user.isDelinquent ? "/Webpages/MDPayment.html" : (user.role === "admin" ? "/Webpages/AdHome.html" : "/Webpages/HoHome.html"),
        });
      });
    });

  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      success: false,
      message: "An error occurred during login",
      error: error.message,
    });
  }
});




app.get("/api/check-auth", (req, res) => {
  console.log("Auth check - Session:", {
    id: req.sessionID,
    user: req.session?.user,
    cookie: req.session?.cookie
  });

  if (!req.session || !req.session.user) {
    return res.json({
      authenticated: false,
      message: "No active session"
    });
  }

  // Touch the session to keep it alive
  req.session.touch();

  // Save any session changes
  req.session.save((err) => {
    if (err) {
      console.error("Error saving session during auth check:", err);
    }

    res.json({
      authenticated: true,
      user: {
        username: req.session.user.username,
        email: req.session.user.email,
        role: req.session.user.role
      },
      sessionID: req.sessionID
    });
  });
});

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
  const { login, password } = req.body;

  try {
    const db = await connectToDatabase();
    const usersCollection = db.collection("acc");
    const homeownersCollection = db.collection("homeowners");
    const addressCollection = db.collection("address");

    // Find user by email or username
    const user = await usersCollection.findOne({
      $or: [
        { email: { $regex: new RegExp(`^${login}$`, "i") } },
        { username: { $regex: new RegExp(`^${login}$`, "i") } },
      ],
    });

    if (!user) {
      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }

    req.session.user = {
      username: user.username,
      email: user.email,
      role: user.role || "homeowner",
    };

    if (user.role === "homeowner" || !user.role) {
      const homeowner = await homeownersCollection.findOne({ email: user.email });
      if (homeowner) {
        let mdAmount = "1500.00"; // Default

        // Get MDAmount from address collection if there's a reference
        if (homeowner.addressId) {
          const address = await addressCollection.findOne({ _id: homeowner.addressId });
          if (address && address.MDAmount) {
            mdAmount = address.MDAmount;
          }
        }

        // Handle Delinquent or Almost Due (case-insensitive)
        const pStatus = (homeowner.PStatus || "").toLowerCase();
        if (pStatus === "delinquent") {
          return res.json({
            success: false,
            isDelinquent: true,
            username: user.username,
            dueAmount: mdAmount,
            message: "Your account has outstanding dues that need to be paid.",
          });
        } else if (pStatus === "almost due") {
          return res.json({
            success: true,
            isAlmostDue: true,
            username: user.username,
            dueAmount: mdAmount,
            message: "Your dues are almost due. Would you like to pay now?",
          });
        }
      }
    }

    await logActivity("login", `User ${user.username} logged in successfully`);

    res.json({
      success: true,
      username: user.username,
      email: user.email,
      role: user.role || "homeowner",
      redirectUrl: user.role === "admin" ? "/AdHome.html" : "/HoHome.html",
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ success: false, message: "An error occurred during login", error: error.message });
  }
});


app.get('/api/get-monthly-due', async (req, res) => {
  try {
    const { username } = req.query; // Ensure we are using the username from the query
    if (!username) {
      return res.status(400).json({ success: false, message: "Username is required" });
    }

    const db = await connectToDatabase();
    const homeownersCollection = db.collection('homeowners');
    const addressCollection = db.collection('address');

    // Find homeowner by username
    const homeowner = await homeownersCollection.findOne({ username });
    if (!homeowner) {
      return res.status(404).json({ success: false, message: "Homeowner not found" });
    }

    // Find address
    const addresses = await addressCollection.find({}).toArray();
    const matchAddress = addresses.find(addr => {
      const hBlock = String(homeowner.Address?.Block?.$numberInt || homeowner.Address?.Block || "");
      const hLot = String(homeowner.Address?.Lot?.$numberInt || homeowner.Address?.Lot || "");
      const hPhase = String(homeowner.Address?.Phase?.$numberInt || homeowner.Address?.Phase || "");
      const aBlock = String(addr.Block?.$numberInt || addr.Block || "");
      const aLot = String(addr.Lot?.$numberInt || addr.Lot || "");
      const aPhase = String(addr.Phase?.$numberInt || addr.Phase || "");
      return hBlock === aBlock && hLot === aLot && hPhase === aPhase;
    });

    const baseDue = parseFloat(matchAddress?.MDAmount?.$numberDouble || matchAddress?.MDAmount || "1500.00");

    // Calculate penalty
    let penalty = 0;
    let daysOverdue = 0;
    if (homeowner.PStatus === "Delinquent" && homeowner.lastPaymentDate) {
      const lastPayment = new Date(homeowner.lastPaymentDate);
      const today = new Date();
      daysOverdue = Math.floor((today - lastPayment) / (1000 * 60 * 60 * 24));
      penalty = daysOverdue * 10;
    }

    res.json({
      success: true,
      baseDue,
      penalty,
      totalDue: baseDue + penalty,
      daysOverdue,
      address: matchAddress,
      homeowner: {
        firstName: homeowner.firstName,
        lastName: homeowner.lastName,
        email: homeowner.email,
        username: homeowner.username
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});


app.post("/api/monthly-dues-payment", upload.single("receipt"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: "No receipt file uploaded",
      });
    }

    // Read the uploaded file
    const filePath = req.file.path;
    const fileBuffer = fs.readFileSync(filePath);

    // Convert the file to Base64
    const base64Image = fileBuffer.toString("base64");
    const mimeType = req.file.mimetype;

    // Construct the MongoDB document
    const paymentData = {
      username: req.body.userName,
      amount: req.body.finalAmount, // Use the finalAmount from the request
      paymentMethod: req.body.paymentMethod,
      receiptImage: `data:${mimeType};base64,${base64Image}`,
      status: "pending", // Initial status is pending until admin approves
      timestamp: new Date(),
    };

    // Save to MongoDB
    const db = await connectToDatabase();
    const paymentsCollection = db.collection("monthlyPayments");
    const result = await paymentsCollection.insertOne(paymentData);

    // Update homeowner status if payment is submitted
    const homeownersCollection = db.collection("homeowners");
    await homeownersCollection.updateOne(
      { email: paymentData.username },
      {
        $set: {
          paymentStatus: "pending",
          lastPaymentId: result.insertedId,
          lastPaymentDate: new Date(),
        },
      }
    );

    // Cleanup the temporary file
    fs.unlinkSync(filePath);

    // Create notification for admin
    await createNotification(
      "admin@avidadb.com", // Admin email
      "monthly_payment",
      `New monthly payment submitted by ${paymentData.userName} (${paymentData.username})`,
      result.insertedId,
    );

    res.status(200).json({
      success: true,
      message: "Payment submitted successfully! Admin will review your payment.",
    });
  } catch (err) {
    console.error("Error handling monthly payment:", err);

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
      message: "Error processing payment. Please try again.",
    });
  }
});

app.post("/api/submit-monthly-payment", upload.single("receipt"), async (req, res) => {
  try {
    const { username, userName, finalAmount, paymentMethod } = req.body

    if (!username || !finalAmount || !paymentMethod || !req.file) {
      return res.status(400).json({ success: false, message: "Missing required fields" })
    }

    // Create payment record
    const payment = {
      email: username,
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
      message: `New monthly dues payment from ${userName} (${username})`,
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
    const db = await connectToDatabase();
    const paymentsCollection = db.collection("monthlyPayments");
    const homeownersCollection = db.collection("homeowners");

    // Fetch payments
    const payments = await paymentsCollection.find({}).toArray();

    // Fetch homeowner details for each payment
    const paymentsWithHomeownerDetails = await Promise.all(payments.map(async (payment) => {
      const homeowner = await homeownersCollection.findOne({ username: payment.username });
      return {
        ...payment,
        firstName: homeowner ? homeowner.firstName : 'N/A',
        lastName: homeowner ? homeowner.lastName : 'N/A',
      };
    }));

    res.json({
      success: true,
      payments: paymentsWithHomeownerDetails,
    });
  } catch (err) {
    console.error("Error fetching payments:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Add this function to your server.js to log the structure of the Address object
function logAddressStructure(address) {
  if (!address) {
    console.log("Address is null or undefined")
    return
  }

  console.log("Address object keys:", Object.keys(address))

  // Log each property and its type
  Object.entries(address).forEach(([key, value]) => {
    console.log(`Address.${key}:`, {
      value: value,
      type: typeof value,
      isObject: typeof value === "object",
      isArray: Array.isArray(value),
      constructor: value && value.constructor ? value.constructor.name : "N/A",
    })

    // If it's an object, log its structure too
    if (typeof value === "object" && value !== null && !Array.isArray(value)) {
      console.log(`Address.${key} properties:`, Object.keys(value))
    }
  })
}

    


app.get("/api/monthly-payments/:id", async (req, res) => {
  try {
    const { id } = req.params;

    if (!id) {
      return res.status(400).json({
        success: false,
        message: "Payment ID is required",
      });
    }

    const db = await connectToDatabase();
    const paymentsCollection = db.collection("monthlyPayments");
    const homeownersCollection = db.collection("homeowners");

    // Find the payment by ID
    const payment = await paymentsCollection.findOne({ _id: new ObjectId(id) });

    if (!payment) {
      return res.status(404).json({
        success: false,
        message: "Payment not found",
      });
    }

    // Find the homeowner details
    const homeowner = await homeownersCollection.findOne({ username: payment.username });

    res.json({
      success: true,
      payment: {
        ...payment,
        firstName: homeowner ? homeowner.firstName : 'N/A',
        lastName: homeowner ? homeowner.lastName : 'N/A',
        address: homeowner ? `Block ${homeowner.Address.Block}, Lot ${homeowner.Address.Lot}, Phase ${homeowner.Address.Phase}` : 'N/A',
      },
    });
  } catch (error) {
    console.error("Error fetching payment details:", error);
    res.status(500).json({
      success: false,
      message: "Error fetching payment details",
    });
  }
});

app.get('/api/monthly-reciept/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const db = await connectToDatabase();
    const paymentsCollection = db.collection('monthlyPayments');
    const homeownersCollection = db.collection('homeowners');

    // Find the payment by ID
    const payment = await paymentsCollection.findOne({ _id: new ObjectId(id) });

    if (!payment) {
      return res.status(404).json({ success: false, message: 'Payment not found' });
    }

    // Find the homeowner by username
    const homeowner = await homeownersCollection.findOne({ username: payment.username });

    if (!homeowner) {
      return res.status(404).json({ success: false, message: 'Homeowner not found' });
    }

    // Respond with payment and homeowner details
    res.json({
      success: true,
      payment: {
        ...payment,
        homeowner: {
          firstName: homeowner.firstName,
          lastName: homeowner.lastName,
          Address: homeowner.Address,
          lastPaymentDate: homeowner.lastPaymentDate
        }
      }
    });
  } catch (error) {
    console.error('Error fetching payment details:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

app.get("/api/monthly-payment-search", async (req, res) => {
  try {
    const db = await connectToDatabase();
    const collection = db.collection("monthlyPayments");

    const { status, search, limit } = req.query;

    const query = {};
    if (status) {
      query.status = status;
    }
    if (search) {
      query.$or = [
        { userName: { $regex: new RegExp(search, 'i') } },
        { userEmail: { $regex: new RegExp(search, 'i') } }
      ];
    }

    const options = {
      sort: { timestamp: -1 },
      limit: parseInt(limit) || 50
    };

    const payments = await collection.find(query, options).toArray();

    // Transform the payments to include the paymentId explicitly
    const transformedPayments = payments.map(payment => ({
      ...payment,
      paymentId: payment._id.toString() // Convert ObjectId to string if needed
    }));

    res.json({
      success: true,
      payments: transformedPayments
    });
  } catch (error) {
    console.error("Error fetching monthly payments:", error);
    res.status(500).json({
      success: false,
      message: "Server error while retrieving payments",
      error: error.message
    });
  }
});




app.post("/api/check-address-exists", async (req, res) => {
  try {
    const { blockNumber, lotNumber, phaseNumber } = req.body;

    if (!blockNumber || !lotNumber || !phaseNumber) {
      return res.status(400).json({
        success: false,
        message: "Block, Lot, and Phase numbers are required"
      });
    }

    const db = await connectToDatabase();
    const homeownersCollection = db.collection("homeowners");

    // Convert inputs to numbers for comparison
    const blockNum = parseInt(blockNumber, 10);
    const lotNum = parseInt(lotNumber, 10);
    const phaseNum = parseInt(phaseNumber, 10);

    console.log("Searching for address:", { blockNum, lotNum, phaseNum });

    // Get all homeowners and manually check the address structure
    const allHomeowners = await homeownersCollection.find({}).toArray();
    console.log(`Found ${allHomeowners.length} total homeowners to check`);

    // Function to safely extract number from various formats
    const extractNumber = (value) => {
      if (value === undefined || value === null) return null;
      
      // If it's already a number
      if (typeof value === 'number') return value;
      
      // If it's a string that can be parsed as a number
      if (typeof value === 'string') {
        const parsed = parseInt(value, 10);
        if (!isNaN(parsed)) return parsed;
      }
      
      // If it's an object with $numberInt property
      if (typeof value === 'object' && value.$numberInt) {
        return parseInt(value.$numberInt, 10);
      }
      
      return null;
    };

    // Manually check each document
    let existingHomeowner = null;
    
    for (const homeowner of allHomeowners) {
      if (!homeowner.Address) continue;
      
      // Handle different possible structures
      let addressObj = homeowner.Address;
      let docBlock, docLot, docPhase;
      
      // Case 1: Address is an object with Block, Lot, Phase properties
      if (typeof addressObj === 'object') {
        docBlock = extractNumber(addressObj.Block);
        docLot = extractNumber(addressObj.Lot);
        docPhase = extractNumber(addressObj.Phase);
      } 
      // Case 2: Address is a string containing block, lot, phase info
      else if (typeof addressObj === 'string') {
        const blockMatch = addressObj.match(/Block\s*(\d+)/i);
        const lotMatch = addressObj.match(/Lot\s*(\d+)/i);
        const phaseMatch = addressObj.match(/Phase\s*(\d+)/i);
        
        docBlock = blockMatch ? parseInt(blockMatch[1], 10) : null;
        docLot = lotMatch ? parseInt(lotMatch[1], 10) : null;
        docPhase = phaseMatch ? parseInt(phaseMatch[1], 10) : null;
      }
      
      // If we found a match
      if (docBlock === blockNum && docLot === lotNum && docPhase === phaseNum) {
        existingHomeowner = homeowner;
        break;
      }
    }

    // Log the result
    console.log("Address check result:", {
      blockNumber,
      lotNumber,
      phaseNumber,
      found: !!existingHomeowner,
      homeownerId: existingHomeowner ? existingHomeowner._id : null
    });

    res.json({
      success: true,
      exists: !!existingHomeowner,
      message: existingHomeowner ? "This address is already taken" : "Address is available"
    });
  } catch (error) {
    console.error("Error checking address:", error);
    res.status(500).json({
      success: false,
      message: "Server error while checking address",
      error: error.message
    });
  }
});

// Approve payment endpoint
app.post("/api/monthly-payments/:id/approve", async (req, res) => {
  try {
    const { id } = req.params;

    const db = await connectToDatabase();
    const paymentsCollection = db.collection("monthlyPayments");
    const homeownersCollection = db.collection("homeowners");

    // Find the payment
    const payment = await paymentsCollection.findOne({ _id: new ObjectId(id) });

    if (!payment) {
      return res.status(404).json({
        success: false,
        message: "Payment not found",
      });
    }

    // Generate a random 6-digit receipt number
    const receiptNumber = Math.floor(100000 + Math.random() * 900000);

    // Retrieve homeowner's address
    const homeowner = await homeownersCollection.findOne({ username: payment.username });
    const address = homeowner ? homeowner.Address : {};
    const block = address.Block?.["$numberInt"] || address.Block || "";
    const lot = address.Lot?.["$numberInt"] || address.Lot || "";
    const phase = address.Phase?.["$numberInt"] || address.Phase || "";
    const customerCode = `${block}${lot}${phase}`;

    // Update payment status
    await paymentsCollection.updateOne(
      { _id: new ObjectId(id) },
      {
        $set: {
          status: "approved",
          approvedAt: new Date(),
          approvedBy: req.session?.user?.username || "admin",
          receiptNumber: receiptNumber,
          customerCode: customerCode,
        },
      },
    );

    // Update homeowner status
    const updateQuery = payment.username ? { username: payment.username } : { email: payment.username };
    try {
      const updateResult = await homeownersCollection.updateOne(
        updateQuery,
        {
          $set: {
            PStatus: "Compliant",
            lastPaymentDate: new Date(),
          },
        },
      );

      console.log("Update result:", updateResult);
    } catch (error) {
      console.error("Error updating homeowner status:", error);
    }

    // Log the approval
    await logActivity("paymentApproval", `Monthly dues payment for ${payment.username || payment.username} approved`);

    // Create notification for the user
    const notificationRecipient = payment.username || payment.username;
    await createNotification(
      notificationRecipient,
      "payment_approved",
      "Your monthly dues payment has been approved. Your account is now active.",
      payment._id,
    );

    res.json({
      success: true,
      message: "Payment approved successfully",
      receiptNumber: receiptNumber,
      customerCode: customerCode,
    });
  } catch (error) {
    console.error("Error approving payment:", error);
    res.status(500).json({
      success: false,
      message: "Error approving payment",
    });
  }
});

// Reject payment endpoint
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
    const paymentsCollection = db.collection("monthlyPayments")

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
      {
        $set: {
          status: "rejected",
          rejectedAt: new Date(),
          rejectedBy: req.session?.user?.username || "admin",
          rejectionReason: reason,
        },
      },
    )

    // Log the rejection
    await logActivity("paymentRejection", `Monthly dues payment for ${payment.username} rejected: ${reason}`)

    // Create notification for the user
    await createNotification(
      payment.username,
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
        { email: payment.username },
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
        payment.username,
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
        payment.username,
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
  try {
    const db = await connectToDatabase();
    const aeventsCollection = db.collection("events");
    const {
      username,
      eventName,
      eventDate,
      startTime,
      endTime,
      amenity,
      guests,
      poolOptions,
      courtOptions,
      clubhouseOptions
    } = req.body;

    // Convert times to 24-hour format for storage and reliable comparison
    // These are new variables; original startTime/endTime are still used for initial Date object validation
    const newStartTime24 = convertTo24HourFormat(startTime);
    const newEndTime24 = convertTo24HourFormat(endTime);

    // Validate required fields
    if (!username || !eventName || !eventDate || !startTime || !endTime || !amenity || !guests) {
      return res.status(400).json({ success: false, message: "Missing required fields" });
    }

    // Validate amenity
    if (typeof amenity !== 'string' || amenity.length === 0) {
      return res.status(400).json({ success: false, message: "An amenity must be selected" });
    }

    // Validate time format and constraints
    const startDateTime = new Date(`${eventDate} ${startTime}`);
    const endDateTime = new Date(`${eventDate} ${endTime}`);

    if (isNaN(startDateTime.getTime()) || isNaN(endDateTime.getTime())) {
      return res.status(400).json({ success: false, message: "Invalid date or time format" });
    }

    if (endDateTime <= startDateTime) {
      return res.status(400).json({ success: false, message: "End time must be after start time" });
    }

    // Validate amenity-specific constraints
    switch (amenity) {
      case 'Pool':
        if (poolOptions) {
          const startHour = startDateTime.getHours();
          const endHour = endDateTime.getHours();
          
          if (poolOptions.type === 'morning') {
            if (startHour < 6 || endHour > 17) {
              return res.status(400).json({ 
                success: false, 
                message: "Pool morning sessions are only available from 6 AM to 5 PM" 
              });
            }
          } else {
            if (startHour < 17 || endHour > 23) {
              return res.status(400).json({ 
                success: false, 
                message: "Pool evening sessions are only available from 5 PM to 11 PM" 
              });
            }
          }
        }
        
        if (guests.number > 30) {
          return res.status(400).json({ 
            success: false, 
            message: "Pool reservations are limited to 30 guests" 
          });
        }
        break;

      case 'Court':
        if (courtOptions) {
          const startHour = startDateTime.getHours();
          const endHour = endDateTime.getHours();
          
          if (startHour < 18 || endHour > 22) {
            return res.status(400).json({ 
              success: false, 
              message: "Court is only available from 6 PM to 10 PM" 
            });
          }
          
          const duration = (endDateTime - startDateTime) / (1000 * 60 * 60);
          if (duration > 4) {
            return res.status(400).json({ 
              success: false, 
              message: "Court reservations are limited to 4 hours" 
            });
          }
        }
        break;

      case 'Clubhouse':
        const startHour = startDateTime.getHours();
        const endHour = endDateTime.getHours();
        
        if (startHour < 6 || endHour > 22) {
          return res.status(400).json({ 
            success: false, 
            message: "Clubhouse is only available from 6 AM to 10 PM" 
          });
        }
        
        if (guests.number > 60) {
          return res.status(400).json({ 
            success: false, 
            message: "Clubhouse reservations are limited to 60 guests" 
          });
        }
        break;
    }

    // Check for overlapping reservations
    const overlappingReservations = await aeventsCollection.find({
      eventDate,
      status: "approved",
      $or: [
        {
          startTime: { $lt: newEndTime24 }, // Use 24-hour format for comparison
          endTime: { $gt: newStartTime24 }   // Use 24-hour format for comparison
        }
      ],
      amenity // Changed from amenities to amenity
    }).toArray();

    if (overlappingReservations.length > 0) {
      return res.status(400).json({ 
        success: false, 
        message: "Selected time slot overlaps with existing reservations" 
      });
    }

    // Calculate total payment
    let totalPayment = 0;
    const paymentDetails = [];

    switch (amenity) {
      case 'Pool':
        const poolBaseRate = 100;
        const poolTotal = guests.number * poolBaseRate;
        totalPayment += poolTotal;
        paymentDetails.push(`Pool: ${guests.number} guests × ₱${poolBaseRate} = ₱${poolTotal}`);
        
        if (poolOptions?.isReserved) {
          totalPayment += 1000;
          paymentDetails.push('Private Pool Reservation: +₱1000');
        }
        break;

      case 'Court':
        const duration = (endDateTime - startDateTime) / (1000 * 60 * 60);
        const courtBaseRate = 300;
        const courtTotal = duration * courtBaseRate;
        totalPayment += courtTotal;
        paymentDetails.push(`Court: ${duration} hours × ₱${courtBaseRate} = ₱${courtTotal}`);
        
        if (courtOptions?.hasLighting) {
          const lightingTotal = duration * 300;
          totalPayment += lightingTotal;
          paymentDetails.push(`Lighting: ${duration} hours × ₱300 = ₱${lightingTotal}`);
        }
        break;

      case 'Clubhouse':
        const clubhouseDuration = (endDateTime - startDateTime) / (1000 * 60 * 60);
        const clubhouseBaseRate = 1000;
        const clubhouseTotal = clubhouseDuration * clubhouseBaseRate;
        totalPayment += clubhouseTotal;
        paymentDetails.push(`Clubhouse: ${clubhouseDuration} hours × ₱${clubhouseBaseRate} = ₱${clubhouseTotal}`);
        
        if (clubhouseOptions?.hasCatering) {
          totalPayment += 2000;
          paymentDetails.push('Catering Service: +₱2000');
        }
        if (clubhouseOptions?.hasSetup) {
          totalPayment += 1000;
          paymentDetails.push('Setup/Cleanup Service: +₱1000');
        }
        break;
    }

    // Create the event
    const event = {
      username,
      eventName,
      eventDate,
      startTime: newStartTime24, // Store in 24-hour format
      endTime: newEndTime24,   // Store in 24-hour format
      amenity,
      guests,
      poolOptions,
      courtOptions,
      clubhouseOptions,
      totalPayment,
      paymentDetails,
      status: "pending",
      createdAt: new Date()
    };

    await aeventsCollection.insertOne(event);

    res.json({ 
      success: true, 
      message: "Event created successfully", 
      eventId: event._id 
    });
  } catch (error) {
    console.error("Error creating event:", error);
    res.status(500).json({ 
      success: false, 
      message: "Failed to create event" 
    });
  }
});

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
      username: req.body.username,
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
      `New monthly payment submitted by ${paymentData.userName} (${paymentData.username})`,
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
    const aeventsCollection = db.collection("aevents")
    const eventpaymentsCollection = db.collection("eventpayments")

    // Get all approved events
    const events = await aeventsCollection.find({ status: "approved" }).sort({ eventDate: 1 }).toArray()
    
    // Get all event payments
    const eventPayments = await eventpaymentsCollection.find().toArray()
    const paidEventsMap = new Map(eventPayments.map(payment => [payment.eventName, true]))

    // Add payment status to each event
    const eventsWithPaymentStatus = events.map(event => ({
      ...event,
      isPaid: paidEventsMap.has(event.eventName)
    }))

    res.json({
      success: true,
      events: eventsWithPaymentStatus,
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
            event.username,
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
        username: event.username,
      })

      // Create notification for payment confirmation
      await createNotification(
        event.username,
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
async function createNotification(username, type, message, relatedId, subject, amenity, eventDetails = {}) {
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

    // Create base notification object
    const notification = {
      username,
      type,
      message,
      relatedId: relatedIdStr,
      timestamp: new Date(),
      read: false,
      isAdminResponse: isAdminResponse,
    }

    // Add type-specific fields
    if (type === "monthly_payment" || type === "payment_approved" || type === "payment_rejected") {
      // For monthly payment notifications, include payment-specific fields
      const today = new Date()
      const nextPaymentDate = new Date(today)
      nextPaymentDate.setDate(today.getDate() + 30) // 30 days from now

      notification.paymentDetails = {
        amount: eventDetails.amount || null,
        paymentDate: today,
        nextPaymentDate: nextPaymentDate,
        penalty: eventDetails.penalty || 0
      }
    } else if (type === "concern" || type === "new_concern" || type === "concern_reply") {
      // For concern notifications, include concern-specific fields
      notification.subject = subject
      notification.replyDate = new Date()
    } else if (type === "payment_required" || type === "payment_confirmed" || type === "event_confirmed") {
      // For event notifications, include event-specific fields
      notification.subject = subject
      notification.amenity = amenity || eventDetails.amenity || null
      notification.eventName = eventDetails.eventName || null
      notification.eventDate = eventDetails.eventDate || null
      notification.startTime = eventDetails.startTime || null
      notification.endTime = eventDetails.endTime || null
      notification.paymentStatus = paymentStatus
    }

    console.log("Creating notification:", JSON.stringify(notification))
    const result = await notificationsCollection.insertOne(notification)
    return result.insertedId
  } catch (error) {
    console.error("Error creating notification:", error)
    return null
  }
}

async function createEventNotification(username, type, message, relatedId, subject, amenity, eventDetails = {}) {
  try {
    const db = await connectToDatabase();
    const notificationsCollection = db.collection("eventNotifications");

    let relatedIdStr = relatedId;
    if (relatedId) {
      if (relatedId instanceof ObjectId) {
        relatedIdStr = relatedId.toString();
      } else if (typeof relatedId !== "string") {
        relatedIdStr = String(relatedId);
      }
    }

    // Create base notification object
    const notification = {
      username,
      type,
      message,
      relatedId: relatedIdStr,
      timestamp: new Date(),
      read: false,
      isAdminResponse: false,
    };

    // Add type-specific fields
    if (type === "EventPaymentRequired" || type === "EventPaymentConfirmed") {
      // For event payment notifications, include event-specific fields
      notification.subject = subject;
      notification.amenity = amenity || eventDetails.amenity || null;
      notification.eventName = eventDetails.eventName || null;
      notification.eventDate = eventDetails.eventDate || null;
      notification.startTime = eventDetails.startTime || null;
      notification.endTime = eventDetails.endTime || null;
      notification.paymentStatus = eventDetails.paymentStatus || "pending";
    }

    console.log("Creating event notification:", JSON.stringify(notification));

    await notificationsCollection.insertOne(notification);
  } catch (error) {
    console.error("Error creating event notification:", error);
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

app.post("/api/logout", (req, res) => {
  console.log("Logout request received")
  console.log("Session before logout:", req.session)

  if (!req.session) {
    console.log("No session found to destroy")
    return res.json({ success: true, message: "No session to logout" })
  }

  req.session.destroy((err) => {
    if (err) {
      console.error("Logout error:", err)
      return res.status(500).json({ success: false, message: "Logout failed" })
    }

    console.log("Session destroyed successfully")
    res.clearCookie("connect.sid", {
      path: "/",
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
    })

    return res.json({ success: true, message: "Logged out successfully" })
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
        const db = await connectToDatabase();
        
        // Get all homeowners
        const homeowners = await db.collection("homeowners").find({}).toArray();
        
        // Get all accounts
        const accounts = await db.collection("acc").find({}, {
            projection: {
                email: 1,
                status: 1,
                _id: 0
            }
        }).toArray();
        
        // Create a map of email to account
        const emailToAccount = {};
        accounts.forEach(account => {
            if (account.email) {
                const email = account.email.toLowerCase().trim();
                emailToAccount[email] = account;
            }
        });
        
        // Add account information to homeowners, excluding sensitive data
        const homeownersWithAccounts = homeowners.map(homeowner => {
            if (homeowner.email) {
                const email = homeowner.email.toLowerCase().trim();
                const account = emailToAccount[email];
                return {
                    ...homeowner,
                    hasAccount: !!account,
                    accountStatus: account ? account.status : null
                };
            }
            return {
                ...homeowner,
                hasAccount: false,
                accountStatus: null
            };
        });
        
        res.json(homeownersWithAccounts);
    } catch (error) {
        console.error("Error fetching homeowners:", error);
        res.status(500).json({ error: "Failed to fetch homeowners" });
    }
});

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

    // Log the email being used for the query and the update data for debugging
    console.log(`Updating homeowner with email: ${email}`)
    console.log("Update data:", updateData)

    const result = await collection.updateOne({ email: email }, { $set: updateData })

    if (result.modifiedCount > 0) {
      const lastName = homeowner.lastName
      await logActivity("homeownerUpdate", `Homeowner with Last Name ${lastName} updated`)
      res.json({ success: true, message: "Homeowner updated successfully" })
    } else {
      // This is the case where the document was found but no changes were made
      // or the document wasn't found at all
      res.json({
        success: false,
        message: result.matchedCount > 0 ? "No changes made to the homeowner" : "No document matched the query",
      })
    }
  } catch (error) {
    console.error("Error updating homeowner:", error)
    res.status(500).json({ success: false, error: "Failed to update homeowner" })
  }
})

app.put("/updateHomeownerById/:id", async (req, res) => {
  const { id } = req.params
  const updateData = req.body

  try {
    const db = await connectToDatabase()
    const database = getClient().db("avidadb")
    const collection = database.collection("homeowners")

    // Convert string ID to ObjectId
    const objectId = new ObjectId(id)

    // Retrieve the homeowner's document to get the last name
    const homeowner = await collection.findOne({ _id: objectId })

    if (!homeowner) {
      return res.json({ success: false, message: "Homeowner not found" })
    }

    const result = await collection.updateOne({ _id: objectId }, { $set: updateData })

    if (result.modifiedCount > 0) {
      const lastName = homeowner.lastName
      await logActivity("homeownerUpdate", `Homeowner with Last Name ${lastName} updated`)
      res.json({ success: true, message: "Homeowner updated successfully" })
    } else {
      res.json({ success: false, message: "No changes made to the homeowner" })
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
    await createEventNotification(
      event.username,
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

app.post("/api/approve-event/:eventId", async (req, res) => {
  const { eventId } = req.params;
  // HomeownerName might be passed from client if not available on event object, guests also
  const { HomeownerName: HomeownerNameFromClient } = req.body;

  if (!eventId) {
    return res.status(400).json({
      success: false,
      message: "Missing event ID",
    });
  }

  try {
    const db = await connectToDatabase();
    const eventsCollection = db.collection("events"); // Pending events collection
    const aeventsCollection = db.collection("aevents"); // Approved events collection

    let eventToApprove;
    try {
      eventToApprove = await eventsCollection.findOne({ _id: new ObjectId(eventId) });
    } catch (e) {
      console.error("Invalid event ID format for approval:", eventId, e);
      return res.status(400).json({ success: false, message: "Invalid event ID format" });
    }

    if (!eventToApprove) {
      return res.status(404).json({
        success: false,
        message: "Event not found in pending list or has already been processed.",
      });
    }
    
    // Destructure details from the fetched event.
    // Note: startTime and endTime from eventToApprove are already in 24-hour "HH:MM" format
    // due to the /addevent route's processing.
    const { username, eventName, eventDate, startTime, endTime, amenity, guests } = eventToApprove;

    if (!username || !eventName || !eventDate || !startTime || !endTime || !amenity) {
        console.error("Fetched event data is incomplete for eventId:", eventId, eventToApprove);
        return res.status(400).json({
            success: false,
            message: "Fetched event data is incomplete. Cannot approve.",
        });
    }

    // Log the fetched event data for debugging
    console.log("Fetched event data:", eventToApprove);

    
    const approvedEventDataForDb = {
      ...eventToApprove, // Spreads all fields from the fetched event
      approvedAt: new Date(),
      status: "approved",
      // startTime and endTime are already in 24-hour "HH:MM" format
    };
    // Remove original _id before inserting into aevents to avoid issues if it was a re-approval attempt (though logic should prevent this)
    // However, it's safer to ensure the new document in aevents gets its own _id.
    const originalId = approvedEventDataForDb._id; // Keep original ID for deletion from 'events'
    delete approvedEventDataForDb._id;


    const insertResult = await aeventsCollection.insertOne(approvedEventDataForDb);
    await eventsCollection.deleteOne({ _id: originalId });

    // Prepare times for user-friendly notification display
    const displayStartTime = convert24HourTo12HourFormat(startTime); // Use startTime from fetched event
    const displayEndTime = convert24HourTo12HourFormat(endTime);   // Use endTime from fetched event
    const timeRangeForSubject = `${displayStartTime}-${displayEndTime}`;

    // Create notification
    if (username) {
      await createEventNotification(
        username,
        "payment_required",
        `Your event "${eventName}" has been approved. Please proceed with the payment.`,
        insertResult.insertedId.toString(), // Use the new _id from aevents collection for relatedId
        `${eventName} on ${eventDate} ${timeRangeForSubject}`,
        amenity,
        { // Pass eventDetails for createNotification to use
            eventName: eventName,
            username: username,
            eventDate: eventDate,
            startTime: displayStartTime, // For notification consistency
            endTime: displayEndTime,   // For notification consistency
            amenity: amenity,
            guests: guests, // Use guests object from the fetched event
            paymentStatus: "pending" // Initial payment status for approved event
        }
      );
    }

    await logActivity("eventApproval", `Event ${eventName} (ID: ${originalId}) approved by admin. New ID in aevents: ${insertResult.insertedId}`);

    res.json({
      success: true,
      message: "Event approved successfully and moved to approved events.",
      approvedEventId: insertResult.insertedId
    });
  } catch (error) {
    console.error("Error approving event:", error);
    res.status(500).json({
      success: false,
      message: "Server error while approving event.",
      error: error.message,
    });
  }
});

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
app.get("/api/aevents-by-name/:eventName", async (req, res) => {
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
app.get('/api/homeowner-payment-details', async (req, res) => {
  try {
    const db = await connectToDatabase();
    const homeownersCollection = db.collection('homeowners');

    // Assuming you have a way to identify the homeowner, e.g., from session or query
    const homeowner = await homeownersCollection.findOne({ /* criteria to find homeowner */ });

    if (!homeowner) {
      return res.status(404).json({ success: false, message: 'Homeowner not found' });
    }

    const { lastPaymentDate, paymentStatus, MDAmount } = homeowner;

    res.json({
      success: true,
      lastPaymentDate,
      paymentStatus,
      MDAmount
    });
  } catch (error) {
    console.error('Error fetching homeowner payment details:', error);
    res.status(500).json({ success: false, message: 'Error fetching homeowner payment details' });
  }
});

app.get('/api/aevents/:eventId', async (req, res) => {
  try {
    const { eventId } = req.params;
    const db = await connectToDatabase();
    const aeventsCollection = db.collection('aevents');

    const event = await aeventsCollection.findOne({ _id: new ObjectId(eventId) });

    if (!event) {
      return res.status(404).json({ success: false, message: 'Event not found' });
    }

    res.json({ success: true, event });
  } catch (error) {
    console.error('Error fetching event by ID:', error);
    res.status(500).json({ success: false, message: 'Error fetching event by ID' });
  }
});



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
      return "/images/clubhouseimg.jpg";
    case "court":
      return "/images/Courtimg.jpg";
    case "pool":
      return "/images/poolimg.png";
    default:
      return "/images/placeholder.jpg";
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
    const username = req.params.email

    if (!username) {
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
        username: username,
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
    try {
        const eventId = req.params.eventId; // Changed from req.params.id to req.params.eventId
        console.log('Fetching event with ID:', eventId);
        
        if (!eventId) {
            return res.status(400).json({
                success: false,
                message: 'Event ID is required'
            });
        }

        const db = await connectToDatabase();
        const eventsCollection = db.collection('events');
        const aeventsCollection = db.collection('aevents');
        
        let event = null;
        let objectId;

        // Try to convert to ObjectId
        try {
            objectId = new ObjectId(eventId);
            console.log('Created ObjectId:', objectId);
        } catch (e) {
            console.log('Invalid ObjectId format:', e.message);
        }

        // First try: Direct ObjectId lookup in both collections
        if (objectId) {
            event = await eventsCollection.findOne({ _id: objectId });
            if (!event) {
                event = await aeventsCollection.findOne({ _id: objectId });
            }
            console.log('ObjectId lookup result:', event ? 'Found' : 'Not found');
        }

        // Second try: String comparison with _id
        if (!event) {
            console.log('Trying string comparison lookup');
            const allEvents = await aeventsCollection.find({}).toArray();
            event = allEvents.find(e => e._id.toString() === eventId);
            console.log('String comparison lookup result:', event ? 'Found' : 'Not found');
        }

        if (event) {
            console.log('Event found:', event);
            res.json({
                success: true,
                event: event
            });
        } else {
            console.log('Event not found after all lookup attempts');
            res.status(404).json({
                success: false,
                message: 'Event not found'
            });
        }
    } catch (error) {
        console.error('Error fetching event details:', error);
        res.status(500).json({
            success: false,
            message: 'Server error while fetching event details',
            error: error.message
        });
    }
});

app.get("/api/notifications", async (req, res) => {
  try {
    console.log("Notifications request received")
    console.log("Session:", req.session)

    // Check if user is authenticated
    if (!req.session || !req.session.user || !req.session.user.username) {
      console.log("User not authenticated for notifications")
      return res.status(401).json({
        success: false,
        error: "Not authenticated",
      })
    }

    const username = req.session.user.username
    console.log("Fetching notifications for user:", username)

    const db = await connectToDatabase()
    const notificationsCollection = db.collection("notifications")

    // Get notifications for the current user only
    const notifications = await notificationsCollection
      .find({
        username: username,
      })
      .sort({ timestamp: -1 })
      .toArray()

    console.log(`Found ${notifications.length} notifications for user ${username}`)

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
      username: req.session.user.username,
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
        username: req.session.user.username, // Ensure we only update this user's notification
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
    const { username,password } = req.body

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: "Username and password are required",
      })
    }

    const db = await connectToDatabase()
    const usersCollection = db.collection("acc")

    // Check if user already exists
    const existingUser = await usersCollection.findOne({
      $or: [{ username }],
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
      username,
      Address,
      phoneNumber,
      landLine,
      paymentStatus,
      homeownerStatus,
      carStickerStatus,
    } = req.body

    if (!firstName || !lastName || !Address || !phoneNumber || !username) {
      return res.status(400).json({
        success: false,
        message: "Missing required homeowner details",
      })
    }

    const db = await connectToDatabase()
    const homeownersCollection = db.collection("homeowners")

    // Check if homeowner already exists
    const existingHomeowner = await homeownersCollection.findOne({ username })

    if (existingHomeowner) {
      return res.status(400).json({
        success: false,
        message: "Homeowner with this username already exists",
      })
    }

    // Create new homeowner
    const newHomeowner = {
      firstName,
      lastName,
      username,
      Address,
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
      query = { PStatus: "Delinquent" }
    } else if (recipientType === "not_paid") {
      query = { PStatus: "Not Paid" }
    } else if (recipientType === "all_delinquent") {
      query = {
        $or: [{ PStatus: "Delinquent" }],
      }
    } else {
      // Default to all delinquent homeowners
      query = {
        $or: [{ PStatus: "Delinquent" }],
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
      if (homeowner.username) {
        notifications.push({
          username: homeowner.username,
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


// ... existing code ...
app.get("/api/get-all-accounts", async (req, res) => {
  try {
    const db = await connectToDatabase();
    const accCollection = db.collection("acc");
    const accounts = await accCollection.find({}).toArray();
    res.json({ success: true, accounts });
  } catch (error) {
    console.error("Error fetching accounts:", error);
    res.status(500).json({ success: false, error: "Internal server error" });
  }
});

app.post("/api/homeowners/generate-account", async (req, res) => {
  try {
    const { firstName, lastName, Address, phoneNumber, landLine, PStatus, carStickerStatus } = req.body;

    if (!firstName || !lastName || !Address || !phoneNumber) {
      return res.status(400).json({
        success: false,
        error: "Missing required fields",
      });
    }

    const db = await connectToDatabase();
    const homeownersCollection = db.collection("homeowners");
    const accCollection = db.collection("acc");

    // Extract block and lot numbers from address
    let blockNumber, lotNumber, phaseNumber;
    if (typeof Address === 'object') {
      blockNumber = Address.Block?.$numberInt || Address.Block;
      lotNumber = Address.Lot?.$numberInt || Address.Lot;
      phaseNumber = Address.Phase?.$numberInt || Address.Phase;
    } else {
      const blockMatch = Address.match(/Block\s+(\d+)/i);
      const lotMatch = Address.match(/Lot\s+(\d+)/i);
      const phaseMatch = Address.match(/Phase\s+(\d+)/i);
      blockNumber = blockMatch ? blockMatch[1] : null;
      lotNumber = lotMatch ? lotMatch[1] : null;
      phaseNumber = phaseMatch ? phaseMatch[1] : null;
    }

    if (!blockNumber || !lotNumber || !phaseNumber) {
      return res.status(400).json({
        success: false,
        error: "Address must contain valid Block, Lot, and Phase numbers",
      });
    }

    // Standardized username: lastname + firstname initial + block + lot + phase
    const username = `${lastName}${firstName.charAt(0)}${blockNumber}${lotNumber}${phaseNumber}`;
    // Generate password: ASC + block + lot + phase + 2025!
    const password = `ASC${blockNumber}${lotNumber}${phaseNumber}2025!`;

    // Ensure username is unique in both acc and homeowners collections
    const existingUser = await accCollection.findOne({ username });
    const existingHomeowner = await homeownersCollection.findOne({ username });
    if (existingUser || existingHomeowner) {
      return res.status(400).json({
        success: false,
        error: "Username already exists. Please try again.",
      });
    }

    // Create account in acc collection
    const hashedPassword = await bcrypt.hash(password, 10);
    await accCollection.insertOne({
      username,
      password: hashedPassword,
      role: "homeowner",
      isHomeowner: "true",
      createdAt: new Date(),
    });

    // Create homeowner record with username
    const homeowner = {
      firstName,
      lastName,
      username,
      Address,
      phoneNumber,
      landLine: landLine || "",
      PStatus: PStatus || "Compliant",
      HStatus: PStatus === "Delinquent" ? "Delinquent" : "Compliant",
      carSticker: carStickerStatus || "undetermined",
      createdAt: new Date(),
    };
    await homeownersCollection.insertOne(homeowner);

    // Log activity
    await logActivity("accountGenerated", `Generated account for homeowner ${firstName} ${lastName}`);

    res.json({
      success: true,
      message: "Account generated successfully",
      account: {
        username,
        password,
      },
    });
  } catch (error) {
    console.error("Error generating homeowner account:", error);
    res.status(500).json({
      success: false,
      error: "Server error while generating account",
    });
  }
});


app.get("/api/generate-payment-report", async (req, res) => {
  try {
    const { type, range, format, startDate, endDate } = req.query;

    const db = await connectToDatabase();
    const homeownersCollection = db.collection("homeowners");
    const addressCollection = db.collection("address");
    const paymentsCollection = db.collection("payments");

    // Setup date filter
    let fromDate = null;
    let toDate = new Date();

    if (range === "last-month") {
      fromDate = new Date();
      fromDate.setMonth(fromDate.getMonth() - 1);
    } else if (range === "last-quarter") {
      fromDate = new Date();
      fromDate.setMonth(fromDate.getMonth() - 3);
    } else if (range === "last-year") {
      fromDate = new Date();
      fromDate.setFullYear(fromDate.getFullYear() - 1);
    } else if (range === "custom" && startDate && endDate) {
      fromDate = new Date(startDate);
      toDate = new Date(endDate);
    }

    const homeowners = await homeownersCollection.find({}).toArray();
    const addresses = await addressCollection.find({}).toArray();
    const payments = await paymentsCollection.find({}).toArray();

    const addressMap = Object.fromEntries(
      addresses.map(a => [a.homeownerId?.toString(), a])
    );

    const excel = officegen("xlsx");
    const sheet = excel.makeNewSheet();
    sheet.name = "Report"; 

    const formatAddress = (addr) => {
      if (!addr) return "";
      const block = addr.Block?.$numberInt || addr.Block || "";
      const lot = addr.Lot?.$numberInt || addr.Lot || "";
      const phase = addr.Phase?.$numberInt || addr.Phase || "";
      return `Block ${block} Lot ${lot} Phase ${phase}`.trim();
    };
    const findMatchingAddress = (homeownerAddress) => {
      if (!homeownerAddress) return null;
    
      const block1 = homeownerAddress.Block?.$numberInt || homeownerAddress.Block || "";
      const lot1 = homeownerAddress.Lot?.$numberInt || homeownerAddress.Lot || "";
      const phase1 = homeownerAddress.Phase?.$numberInt || homeownerAddress.Phase || "";
    
      return addresses.find(addr => {
        const block2 = addr.Block?.$numberInt || addr.Block || "";
        const lot2 = addr.Lot?.$numberInt || addr.Lot || "";
        const phase2 = addr.Phase?.$numberInt || addr.Phase || "";
    
        const match = block1 == block2 && lot1 == lot2 && phase1 == phase2;
        if (match) {
          console.log(`✅ Match found: Block ${block2}, Lot ${lot2}, Phase ${phase2}, Amount: ${addr.MDAmount}`);
        }
        return match;
      });
    };
    

    let headers = [];
    let rows = [];

    if (type === "delinquent_owners") {
      headers = [
        "Last Name", "First Name", "Address", "Phone Number", "Landline",
        "Amount Due", "Last Paid", "Payment Status", "Homeowner Status", "Car Sticker Status"
      ];
    
      homeowners.forEach(h => {
        const status = h.PStatus?.toLowerCase();
        if (status !== "delinquent") return;
    
        const matchedAddr = findMatchingAddress(h.Address);

        rows.push([
          h.lastName || "",
          h.firstName || "",
          formatAddress(h.Address),
          h.phoneNumber || "",
          h.landline || "",
          matchedAddr?.MDAmount?.$numberDouble || matchedAddr?.MDAmount || 0,
          h.lastPaymentDate ? new Date(h.lastPaymentDate).toLocaleDateString() : "",
          h.PStatus || "",
          h.HStatus || "",
          h.carSticker || "Undetermined"
        ]);
        
      });
    }
    else if (type === "payment_history") {
      headers = [
        "Homeowner", "Email", "Amount", "Payment Method", "Date", "Status"
      ];

      payments.forEach(p => {
        const paymentDate = new Date(p.timestamp);
        if (fromDate && (paymentDate < fromDate || paymentDate > toDate)) return;

        rows.push([
          String(p.userName || ""),
          String(p.userEmail || ""),
          p.amount || 0,
          String(p.paymentMethod || ""),
          paymentDate.toLocaleDateString(),
          String(p.status || "")
        ]);
      });

    } else if (type === "homeowner_details") {
      headers = [
        "Last Name", "First Name", "Email", "Phone", "Landline", "Address",
        "Homeowner Status", "Car Sticker Status", "Monthly Due"
      ];

      homeowners.forEach(h => {
        const addr = formatAddress(h.Address || addressMap[h._id?.toString()]);
        rows.push([
          String(h.lastName || ""),
          String(h.firstName || ""),
          String(h.email || ""),
          String(h.phoneNumber || ""),
          String(h.landLine || ""),
          addr,
          String(h.homeownerStatus || ""),
          String(h.carStickerStatus || "Undetermined"),
          h.MDAmount || 0
        ]);
      });

    } else if (type === "monthly_summary") {
      headers = [
        "Month", "Total Payments", "Total Amount Collected"
      ];

      const summaryMap = {};

      payments.forEach(p => {
        const paymentDate = new Date(p.timestamp);
        if (fromDate && (paymentDate < fromDate || paymentDate > toDate)) return;

        const key = `${paymentDate.getFullYear()}-${String(paymentDate.getMonth() + 1).padStart(2, "0")}`;
        if (!summaryMap[key]) {
          summaryMap[key] = { count: 0, total: 0 };
        }
        summaryMap[key].count++;
        summaryMap[key].total += p.amount || 0;
      });

      rows = Object.entries(summaryMap).map(([month, data]) => [
        month,
        data.count,
        data.total
      ]);
    }

    // Final check: align rows to headers
    const expectedCols = headers.length;
    rows = rows.filter(r => Array.isArray(r) && r.length === expectedCols);

    sheet.data[0] = headers;
    rows.forEach((row, idx) => {
      sheet.data[idx + 1] = row;
    });

    const filename = `report-${type}-${Date.now()}.${format === "csv" ? "csv" : "xlsx"}`;
    if (format === "csv") {
      res.setHeader("Content-Type", "text/csv");
    } else {
      res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
    }
    res.setHeader("Content-Disposition", `attachment; filename=${filename}`);

    excel.generate(res);
  } catch (error) {
    console.error("Error generating report:", error);
    res.status(500).json({
      success: false,
      message: "Failed to generate report",
      error: error.message
    });
  }
});

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

//generate otp

const generateOTP = () => {
  return Math.floor(1000 + Math.random() * 9000) //4 otp
}

//otp sending

app.post("/send-otp", (req, res) => {
  const username = req.body.email

  const otp = generateOTP()

  // Assuming you have configured transporter (nodemailer) elsewhere

  const mailOptions = {
    from: "test@mail", // Replace with your email address

    to: username,

    subject: "Your OTP Code",

    text: `Your OTP code is: ${otp}`,
  }

  // transporter.sendMail(mailOptions, (error, info) => { ... }); // Uncomment and implement if you have nodemailer setup

  res.json({ success: true, message: "OTP sent successfully", otp }) // Send OTP in response for testing
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

const { handleCreateAccounts, handleGetHomeownerCredentials } = require("./create-homeowner-accounts")

app.post("/api/admin/create-homeowner-accounts", async (req, res) => {
  // Check if user is admin
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).json({
      success: false,
      message: "Unauthorized. Admin access required.",
    })
  }

  await handleCreateAccounts(req, res)
})

// Route to get homeowner credentials
app.get("/api/admin/homeowner-credentials/:id", async (req, res) => {
  // Check if user is admin
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).json({
      success: false,
      message: "Unauthorized. Admin access required.",
    })
  }

  await handleGetHomeownerCredentials(req, res)
})

// Route to reset homeowner password
app.post("/api/admin/reset-homeowner-password/:id", async (req, res) => {
  // Check if user is admin
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).json({
      success: false,
      message: "Unauthorized. Admin access required.",
    })
  }

  req.query.resetPassword = "true"
  await handleGetHomeownerCredentials(req, res)
})

// Add this new endpoint to get all homeowner credentials
app.get("/api/homeowners/credentials", async (req, res) => {
  try {
    // Check if user is admin
    if (!req.session.user || req.session.user.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Unauthorized. Admin access required.",
      })
    }

    const db = await connectToDatabase()
    const homeownersCollection = db.collection("homeowners")
    const accountsCollection = db.collection("acc")

    // Get all homeowners
    const homeowners = await homeownersCollection.find({}).toArray()

    // Get all accounts
    const accounts = await accountsCollection.find({}).toArray()

    // Create a map of email to account details
    const accountMap = {}
    accounts.forEach((account) => {
      accountMap[account.email] = account
    })

    // Combine homeowner and account information
    const credentials = homeowners.map((homeowner) => {
      const account = accountMap[homeowner.email] || {}
      return {
        _id: homeowner._id,
        firstName: homeowner.firstName,
        lastName: homeowner.lastName,
        address: homeowner.Address,
        username: account.username || homeowner.email,
        password: "********", // For security, don't send actual passwords
      }
    })

    res.json({
      success: true,
      credentials,
    })
  } catch (error) {
    console.error("Error fetching homeowner credentials:", error)
    res.status(500).json({
      success: false,
      message: "Failed to fetch homeowner credentials",
      error: error.message,
    })
  }
})

// Add this new endpoint to get homeowner credentials
app.get("/api/homeowner-credentials/:id", async (req, res) => {
  try {
    // Check if user is authenticated as admin
    if (!req.session || !req.session.user || req.session.user.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Unauthorized. Only administrators can view credentials.",
      })
    }

    const { id } = req.params
    const resetPassword = req.query.resetPassword === "true"

    if (!id) {
      return res.status(400).json({
        success: false,
        message: "Homeowner ID is required",
      })
    }

    const db = await connectToDatabase()
    const homeownersCollection = db.collection("homeowners")
    const accCollection = db.collection("acc")

    // Find the homeowner by ID
    const homeowner = await homeownersCollection.findOne({ _id: new ObjectId(id) })

    if (!homeowner) {
      return res.status(404).json({
        success: false,
        message: "Homeowner not found",
      })
    }

    // Find the account by email
    const account = await accCollection.findOne({ email: homeowner.email })

    if (!account) {
      return res.status(404).json({
        success: false,
        message: "Account not found for this homeowner",
      })
    }

    // If reset password is requested, generate a new password
    let newPassword = null
    if (resetPassword) {
      // Extract block and lot numbers from address for password generation
      const blockMatch = homeowner.Address.match(/Block\s+(\d+)/i)
      const lotMatch = homeowner.Address.match(/Lot\s+(\d+)/i)

      if (blockMatch && lotMatch) {
        const blockNumber = blockMatch[1]
        const lotNumber = lotMatch[1]
        const currentYear = new Date().getFullYear()

        // Generate password in the format: ASC<Block><Lot><Year>!
        newPassword = `ASC${blockNumber}${lotNumber}${currentYear}!`

        // Hash the new password
        const hashedPassword = await bcrypt.hash(newPassword, 10)

        // Update the account with the new password
        await accCollection.updateOne({ _id: account._id }, { $set: { password: hashedPassword } })

        // Log the password reset
        await logActivity(
          "passwordReset",
          `Admin reset password for homeowner ${homeowner.firstName} ${homeowner.lastName}`,
        )
      } else {
        return res.status(400).json({
          success: false,
          message: "Could not reset password: Address does not contain valid Block and Lot numbers",
        })
      }
    }

    // Return account details
    res.json({
      success: true,
      homeownerId: homeowner._id,
      username: account.username,
      email: account.email,
      newPassword: newPassword, // Will be null if no reset was requested
    })
  } catch (error) {
    console.error("Error fetching homeowner credentials:", error)
    res.status(500).json({
      success: false,
      message: "Error fetching homeowner credentials",
      error: error.message,
    })
  }
})

// Add this endpoint to reset a homeowner's password
app.post("/api/reset-homeowner-password/:id", async (req, res) => {
  try {
    // Check if user is authenticated as admin
    if (!req.session || !req.session.user || req.session.user.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Unauthorized. Only administrators can reset passwords.",
      })
    }

    const { id } = req.params

    if (!id) {
      return res.status(400).json({
        success: false,
        message: "Homeowner ID is required",
      })
    }

    // Redirect to the credentials endpoint with reset flag
    req.query.resetPassword = "true"
    return await getHomeownerCredentials(req, res)
  } catch (error) {
    console.error("Error resetting homeowner password:", error)
    res.status(500).json({
      success: false,
      message: "Error resetting homeowner password",
      error: error.message,
    })
  }
})

// Extract the homeowner credentials logic to a reusable function
async function getHomeownerCredentials(req, res) {
  try {
    const { id } = req.params
    const resetPassword = req.query.resetPassword === "true"

    if (!id) {
      return res.status(400).json({
        success: false,
        message: "Homeowner ID is required",
      })
    }

    const db = await connectToDatabase()
    const homeownersCollection = db.collection("homeowners")
    const accCollection = db.collection("acc")

    // Find the homeowner by ID
    const homeowner = await homeownersCollection.findOne({ _id: new ObjectId(id) })

    if (!homeowner) {
      return res.status(404).json({
        success: false,
        message: "Homeowner not found",
      })
    }

    // Find the account by email
    const account = await accCollection.findOne({ email: homeowner.email })

    if (!account) {
      return res.status(404).json({
        success: false,
        message: "Account not found for this homeowner",
      })
    }

    // If reset password is requested, generate a new password
    let newPassword = null
    if (resetPassword) {
      // Extract block and lot numbers from address for password generation
      const blockMatch = homeowner.Address.match(/Block\s+(\d+)/i)
      const lotMatch = homeowner.Address.match(/Lot\s+(\d+)/i)

      if (blockMatch && lotMatch) {
        const blockNumber = blockMatch[1]
        const lotNumber = lotMatch[1]
        const currentYear = new Date().getFullYear()

        // Generate password in the format: ASC<Block><Lot><Year>!
        newPassword = `ASC${blockNumber}${lotNumber}${currentYear}!`

        // Hash the new password
        const hashedPassword = await bcrypt.hash(newPassword, 10)

        // Update the account with the new password
        await accCollection.updateOne({ _id: account._id }, { $set: { password: hashedPassword } })

        // Log the password reset
        await logActivity(
          "passwordReset",
          `Admin reset password for homeowner ${homeowner.firstName} ${homeowner.lastName}`,
        )
      } else {
        return res.status(400).json({
          success: false,
          message: "Could not reset password: Address does not contain valid Block and Lot numbers",
        })
      }
    }

    // Return account details
    res.json({
      success: true,
      homeownerId: homeowner._id,
      username: account.username,
      email: account.email,
      newPassword: newPassword, // Will be null if no reset was requested
    })
  } catch (error) {
    console.error("Error in getHomeownerCredentials:", error)
    res.status(500).json({
      success: false,
      message: "Error processing homeowner credentials",
      error: error.message,
    })
  }
}

// Export the function for use in other files
module.exports = {
  connectToDatabase,
  getHomeownerCredentials,
}

// === Static File Serving (place this at the end of the file) ===

app.get("/api/homeowners/delinquent", async (req, res) => {
  try {
    // Debug logging
    console.log("=== Delinquent Homeowners Request ===");
    console.log("Session:", req.session);
    console.log("User:", req.session?.user);

    // Check if user is authenticated
    if (!req.session?.user) {
      console.log("No session or user found");
      return res.status(401).json({
        success: false,
        message: "Unauthorized access - Please log in"
      });
    }

    // Check if user is an admin
    if (req.session.user.role !== "admin") {
      console.log("User is not an admin:", req.session.user.role);
      return res.status(403).json({
        success: false,
        message: "Admin access required"
      });
    }

    const db = await connectToDatabase();
    const homeownersCollection = db.collection("homeowners");
    
    // Get pagination parameters
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    
    // Build search query if provided
    let query = {
      $or: [
        { paymentStatus: "Delinquent" },
        { homeownerStatus: "Delinquent" },
        { paymentStatus: "Not Paid" }
      ]
    };
    
    if (req.query.search) {
      const searchRegex = new RegExp(req.query.search, "i");
      query.$and = [
        {
          $or: [
            { firstName: searchRegex },
            { lastName: searchRegex },
            { email: searchRegex }
          ]
        }
      ];
    }
    
    console.log("Query:", query);
    
    // Get total count for pagination
    const totalHomeowners = await homeownersCollection.countDocuments(query);
    console.log("Total homeowners found:", totalHomeowners);
    
    // Get delinquent homeowners with pagination
    const homeowners = await homeownersCollection
      .find(query)
      .sort({ lastPaymentDate: 1 }) // Sort by last payment date ascending
      .skip(skip)
      .limit(limit)
      .toArray();
    
    console.log("Homeowners found:", homeowners.length);
    
    // Format the response
    const formattedHomeowners = homeowners.map(homeowner => ({
      _id: homeowner._id,
      name: `${homeowner.firstName || ''} ${homeowner.lastName || ''}`.trim(),
      email: homeowner.email,
      monthlyDue: homeowner.monthlyDue || "5000.00",
      lastPaymentDate: homeowner.lastPaymentDate || homeowner.createdAt,
      paymentMethod: homeowner.paymentMethod || "Not specified",
      paymentStatus: homeowner.paymentStatus,
      homeownerStatus: homeowner.homeownerStatus
    }));
    
    const response = {
      success: true,
      homeowners: formattedHomeowners,
      currentPage: page,
      totalPages: Math.ceil(totalHomeowners / limit),
      totalHomeowners
    };
    
    console.log("Sending response:", JSON.stringify(response));
    return res.json(response);
    
  } catch (error) {
    console.error("Error fetching delinquent homeowners:", error);
    return res.status(500).json({
      success: false,
      message: "Error fetching delinquent homeowners",
      error: error.message
    });
  }
});

app.get("/break-auth-loop", (req, res) => {
  // Clear the session
  req.session.destroy()

  // Send a response with instructions
  res.send(`
    <html>
      <head>
        <title>Auth Loop Broken</title>
        <style>
          body {
            font-family: Arial, sans-serif;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            text-align: center;
          }
          h1 { color: #AF2630; }
          .btn {
            display: inline-block;
            background-color: #AF2630;
            color: white;
            padding: 10px 20px;
            text-decoration: none;
            border-radius: 5px;
            margin-top: 20px;
          }
        </style>
      </head>
      <body>
        <h1>Authentication Loop Broken</h1>
        <p>The authentication loop has been broken. Please try logging in again.</p>
        <a href="/login.html" class="btn">Go to Login Page</a>
        <script>
          // Clear any local storage or session storage that might be causing issues
          localStorage.clear();
          sessionStorage.clear();
        </script>
      </body>
    </html>
  `)
})




// Custom middleware to handle API requests before serving static files

app.use((req, res, next) => {
  // If the request is for a static file, let express.static handle it
  if (req.path.startsWith('/images/') || 
      req.path.startsWith('/CSS/') || 
      req.path.startsWith('/Webpages/')) {
    return express.static(path.join(__dirname))(req, res, next);
  }
  next();
});


// Add this endpoint to serve static files with authentication check
app.get("/admin/*", (req, res, next) => {
  if (req.session && req.session.user && req.session.user.role === "admin") {
    next() // Allow access to admin pages
  } else {
    res.redirect("/login.html") // Redirect to login if not authenticated as admin
  }
})



app.use((req, res, next) => {
  const oldJson = res.json

  res.json = (data) => {
    console.log("Response data:", JSON.stringify(data))

    // Fix: Pass data as an array
    oldJson.apply(res, [data])
  }

  next()
})

// ... existing code ...

// Add session check middleware
const requireAuth = (req, res, next) => {
  console.log("=== Auth Check ===");
  console.log("Session:", req.session);
  console.log("User:", req.session?.user);
  console.log("Cookies:", req.headers.cookie);
  console.log("=================");

  if (!req.session || !req.session.user) {
    console.log("No session or user found - redirecting to login");
    return res.status(401).json({
      success: false,
      message: "Authentication required",
      redirect: "/login.html"
    });
  }
  next();
};

const requireAdmin = (req, res, next) => {
  if (!req.session?.user?.role || req.session.user.role !== "admin") {
    console.log("Non-admin access attempt");
    return res.status(403).json({
      success: false,
      message: "Admin access required",
      redirect: "/login.html?unauthorized=true"
    });
  }
  next();
};

// Apply middleware to protected routes
app.use([
  "/Webpages/AdHome.html",
  "/Webpages/admincalender.html",
  "/Webpages/analytics.html",
  "/Webpages/hotable.html",
  "/Webpages/MonthlyPayments.html"
], requireAuth, requireAdmin);

app.use([
  "/Webpages/HoHome.html",
  "/Webpages/homeowner-dashboard.html",
  "/api/user-events"
], (req, res, next) => {
  if (!req.session || !req.session.user) {
    console.log("No session or user found - redirecting to login");
    return res.status(401).json({
      success: false,
      message: "Authentication required",
      redirect: "/login.html"
    });
  }
  next();
});

// Authentication middleware
const checkAuth = (req, res, next) => {
  if (!req.session || !req.session.user) {
    console.log("No session or user found - redirecting to login");
    return res.status(401).json({
      success: false,
      message: "Authentication required",
      redirect: "/login.html"
    });
  }
  next();
};

// Role-based access control middleware
const checkRole = (allowedRoles) => {
  return (req, res, next) => {
    if (!req.session?.user?.role || 
        !allowedRoles.includes(req.session.user.role.toLowerCase())) {
      console.log(`Invalid role: ${req.session.user.role}`);
      return res.status(403).json({
        success: false,
        message: "Unauthorized role",
        redirect: "/login.html?unauthorized=true"
      });
    }
    next();
  };
};

// Apply middleware to routes
app.use([
  "/Webpages/HoHome.html",
  "/Webpages/homeowner-dashboard.html",
  "/api/user-events"
], checkAuth);

// Admin and guard only routes
app.use([
  "/Webpages/AdHome.html",
  "/Webpages/admincalender.html",
  "/Webpages/analytics.html",
  "/Webpages/hotable.html",
  "/Webpages/MonthlyPayments.html"
], checkAuth, checkRole(['admin', 'guard']));

// Add dashboard access endpoint
app.post('/api/check-dashboard-access', async (req, res) => {
  const { password } = req.body;
  
  try {
    console.log('Checking dashboard access...');
    const db = await connectToDatabase();
    const usersCollection = db.collection("acc");
    
    // First try to find an admin or guard user
    const user = await usersCollection.findOne({
      $or: [
        { role: 'admin' },
        { role: { $regex: new RegExp('^guard$', 'i') } }
      ]
    });
    
    if (!user) {
      console.log('No admin or guard user found');
      return res.json({
        success: false,
        message: 'Invalid credentials. Only Admin and Guard can access the dashboard.'
      });
    }

    // Compare password
    const isValidPassword = await bcrypt.compare(password, user.password);
    console.log('Password check:', isValidPassword ? 'Valid' : 'Invalid');

    if (isValidPassword) {
      // Create a session for the user
      req.session.regenerate((err) => {
        if (err) {
          console.error('Error creating session:', err);
          return res.json({
            success: false,
            message: 'Error creating session'
          });
        }

        req.session.user = {
          username: user.username,
          email: user.email,
          role: user.role
        };

        req.session.save((err) => {
          if (err) {
            console.error('Error saving session:', err);
            return res.json({
              success: false,
              message: 'Error saving session'
            });
          }

          console.log(`${user.role} access granted`);
          res.json({
            success: true,
            role: user.role,
            redirectUrl: '/Webpages/homeowner-dashboard.html'
          });
        });
      });
    } else {
      console.log('Invalid password');
      res.json({
        success: false,
        message: 'Invalid password. Only Admin and Guard can access the dashboard.'
      });
    }
  } catch (error) {
    console.error('Error checking dashboard access:', error);
    res.status(500).json({
      success: false,
      message: 'An error occurred while checking access.'
    });
  }
});

app.get('/api/homeowners/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    if (!id) {
      return res.status(400).json({
        success: false,
        message: 'Homeowner ID is required'
      });
    }
    
    const db = await connectToDatabase();
    const homeownersCollection = db.collection('homeowners');
    const addressCollection = db.collection('address');
    
    // Find the homeowner by ID
    const homeowner = await homeownersCollection.findOne({ _id: new ObjectId(id) });
    
    if (!homeowner) {
      return res.status(404).json({
        success: false,
        message: 'Homeowner not found'
      });
    }
    
    // Get the Block, Lot, Phase values from the homeowner's Address
    let block = null, lot = null, phase = null;
    
    if (homeowner.Address) {
      if (homeowner.Address.Block) {
        block = homeowner.Address.Block.$numberInt || homeowner.Address.Block;
      }
      if (homeowner.Address.Lot) {
        lot = homeowner.Address.Lot.$numberInt || homeowner.Address.Lot;
      }
      if (homeowner.Address.Phase) {
        phase = homeowner.Address.Phase.$numberInt || homeowner.Address.Phase;
      }
    }
    
    // Find matching address record
    let addressRecord = null;
    if (block !== null && lot !== null && phase !== null) {
      addressRecord = await addressCollection.findOne({
        $or: [
          {
            "Block.$numberInt": block.toString(),
            "Lot.$numberInt": lot.toString(),
            "Phase.$numberInt": phase.toString()
          },
          {
            Block: parseInt(block),
            Lot: parseInt(lot),
            Phase: parseInt(phase)
          }
        ]
      });
    }
    
    // Get MDAmount from address record
    let mdAmount = "1500.00";
    if (addressRecord && addressRecord.MDAmount) {
      if (addressRecord.MDAmount.$numberDouble) {
        mdAmount = addressRecord.MDAmount.$numberDouble;
      } else if (typeof addressRecord.MDAmount === 'number') {
        mdAmount = addressRecord.MDAmount.toFixed(2);
      }
    }
    
    // Add MDAmount to homeowner data
    const enhancedHomeowner = {
      ...homeowner,
      MDAmount: mdAmount
    };
    
    res.json({
      success: true,
      homeowner: enhancedHomeowner
    });
  } catch (error) {
    console.error('Error fetching homeowner details:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching homeowner details'
    });
  }
});



app.post('/api/homeowners/:id/reminder', async (req, res) => {
  try {
    const { id } = req.params;
    
    if (!id) {
      return res.status(400).json({
        success: false,
        message: 'Homeowner ID is required'
      });
    }
    
    const db = await connectToDatabase();
    const homeownersCollection = db.collection('homeowners');
    
    // Find the homeowner by ID
    const homeowner = await homeownersCollection.findOne({ _id: new ObjectId(id) });
    
    if (!homeowner) {
      return res.status(404).json({
        success: false,
        message: 'Homeowner not found'
      });
    }

    // In a real application, you would send an email or notification here
    console.log(`Sending payment reminder to ${homeowner.firstName} ${homeowner.lastName} (${homeowner.email})`);
    
    // Log the activity
    await logActivity('paymentReminder', `Payment reminder sent to ${homeowner.firstName} ${homeowner.lastName}`);

    res.json({
      success: true,
      message: 'Payment reminder sent successfully'
    });
  } catch (error) {
    console.error('Error sending payment reminder:', error);
    res.status(500).json({
      success: false,
      message: 'Error sending payment reminder'
    });
  }
});

// Add this route before your other routes to test database connection
app.get('/api/test-database', async (req, res) => {
  try {
    console.log('Testing database connection...');
    
    // Get client and database
    const client = getClient();
    console.log('Client type:', typeof client);
    console.log('Client properties:', Object.keys(client));
    
    // Try to get the database
    const db = client.db();
    console.log('Database type:', typeof db);
    console.log('Database properties:', Object.keys(db));
    
    // List collections to verify connection works
    const collections = await db.listCollections().toArray();
    console.log('Collections in database:');
    collections.forEach(col => console.log(`- ${col.name}`));
    
    // Check if homeowners collection exists
    const hasHomeowners = collections.some(col => col.name === 'homeowners');
    
    // If it exists, try to count documents
    let homeownersCount = 0;
    if (hasHomeowners) {
      homeownersCount = await db.collection('homeowners').countDocuments();
      console.log(`Homeowners collection has ${homeownersCount} documents`);
    }
    
    res.json({
      success: true,
      message: 'Database connection test successful',
      databaseInfo: {
        collections: collections.map(col => col.name),
        hasHomeownersCollection: hasHomeowners,
        homeownersCount: homeownersCount
      }
    });
  } catch (error) {
    console.error('Database test error:', error);
    res.status(500).json({
      success: false,
      message: 'Database connection test failed',
      error: error.message,
      stack: error.stack
    });
  }
});


// Add this route handler for checking homeowners with due payments
app.get('/api/check-homeowners-due', async (req, res) => {
  try {
    console.log('=== Check Homeowners Due API Request ===');
    
    // Check if user is authenticated
    if (!req.session || !req.session.user) {
      return res.status(401).json({
        success: false,
        message: "Authentication required"
      });
    }
    
    const db = await connectToDatabase();
    const homeownersCollection = db.collection('homeowners');
    const addressCollection = db.collection('address');
    
    // Query for homeowners with Almost Due or Delinquent status
    const query = {
      $or: [
        { PStatus: "Almost Due" },
        { PStatus: "Delinquent" }
      ]
    };
    
    // Add search functionality if provided
    if (req.query.search) {
      const searchRegex = new RegExp(req.query.search, 'i');
      query.$and = [
        {
          $or: [
            { firstName: searchRegex },
            { lastName: searchRegex },
            { email: searchRegex }
          ]
        }
      ];
    }
    
    console.log('Query:', JSON.stringify(query));
    
    // Get pagination parameters
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    
    // Get total count for pagination
    const totalHomeowners = await homeownersCollection.countDocuments(query);
    console.log(`Found ${totalHomeowners} homeowners with due payments`);
    
    // Get homeowners matching the query with pagination
    const homeowners = await homeownersCollection
      .find(query)
      .sort({ lastPaymentDate: 1 })
      .skip(skip)
      .limit(limit)
      .toArray();
    
    console.log(`Retrieved ${homeowners.length} homeowners for this page`);
    
    // Process each homeowner to add address information
    const enhancedHomeowners = await Promise.all(homeowners.map(async (homeowner) => {
      // Calculate days since last payment
      const lastPaymentDate = homeowner.lastPaymentDate ? new Date(homeowner.lastPaymentDate) : new Date();
      const today = new Date();
      const daysSincePayment = Math.floor((today - lastPaymentDate) / (1000 * 60 * 60 * 24));
      
      // Get the Block, Lot, Phase values from the homeowner's Address
      let block = null, lot = null, phase = null;
      
      if (homeowner.Address) {
        if (homeowner.Address.Block) {
          block = homeowner.Address.Block.$numberInt || homeowner.Address.Block;
        }
        if (homeowner.Address.Lot) {
          lot = homeowner.Address.Lot.$numberInt || homeowner.Address.Lot;
        }
        if (homeowner.Address.Phase) {
          phase = homeowner.Address.Phase.$numberInt || homeowner.Address.Phase;
        }
      }
      
      // Find matching address record
      let addressRecord = null;
      if (block !== null && lot !== null && phase !== null) {
        addressRecord = await addressCollection.findOne({
          "Block.$numberInt": block.toString(),
          "Lot.$numberInt": lot.toString(),
          "Phase.$numberInt": phase.toString()
        });
        
        // If not found with $numberInt format, try direct number comparison
        if (!addressRecord) {
          addressRecord = await addressCollection.findOne({
            $or: [
              {
                "Block.$numberInt": block.toString(),
                "Lot.$numberInt": lot.toString(),
                "Phase.$numberInt": phase.toString()
              },
              {
                Block: parseInt(block),
                Lot: parseInt(lot),
                Phase: parseInt(phase)
              }
            ]
          });
        }
      }
      
      // Get MDAmount from address record
      let mdAmount = "1500.00";
      if (addressRecord && addressRecord.MDAmount) {
        if (addressRecord.MDAmount.$numberDouble) {
          mdAmount = addressRecord.MDAmount.$numberDouble;
        } else if (typeof addressRecord.MDAmount === 'number') {
          mdAmount = addressRecord.MDAmount.toFixed(2);
        }
      }
      
      return {
        _id: homeowner._id,
        firstName: homeowner.firstName,
        lastName: homeowner.lastName,
        email: homeowner.email || "",
        Address: homeowner.Address,
        phoneNumber: homeowner.phoneNumber,
        PStatus: homeowner.PStatus,
        lastPaymentDate: lastPaymentDate,
        daysSincePayment: daysSincePayment,
        delinquentSince: homeowner.delinquentSince || "",
        MDAmount: mdAmount
      };
    }));
    
    res.json({
      success: true,
      homeowners: enhancedHomeowners,
      totalPages: Math.ceil(totalHomeowners / limit),
      currentPage: page
    });
  } catch (error) {
    console.error('Error fetching homeowners with due payments:', error);
    res.status(500).json({
      success: false,
      message: error.message
    });
  }
});


// Add the reminder endpoint
app.post('/api/homeowners/:id/reminder', async (req, res) => {
  try {
    const { id } = req.params;
    console.log('Sending reminder for homeowner:', id);
    
    // Get database properly
    const client = getClient();
    const db = client.db();
    
    // Find the homeowner - use ObjectId if your IDs are MongoDB ObjectIds
    const homeowner = await db.collection('homeowners').findOne({ 
      _id: new ObjectId(id) 
    });
    
    if (!homeowner) {
      console.log('Homeowner not found:', id);
      return res.status(404).json({
        success: false,
        message: 'Homeowner not found'
      });
    }
    
    console.log('Found homeowner:', homeowner.firstName, homeowner.lastName);
    
    // Simplified reminder - in reality, you'd send an email or notification
    console.log('Reminder would be sent to:', homeowner.email);
    
    // Log activity
    await db.collection('activity_logs').insertOne({
      type: 'payment_reminder',
      homeownerId: homeowner._id,
      homeownerName: `${homeowner.firstName} ${homeowner.lastName}`,
      timestamp: new Date(),
      details: 'Payment reminder sent'
    });
    
    res.json({
      success: true,
      message: 'Payment reminder sent successfully'
    });
  } catch (error) {
    console.error('Error sending reminder:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to send payment reminder: ' + error.message
    });
  }
});


// Serve static files AFTER API routes



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

async function connectToDatabase() {
  try {
    if (database) {
      return database;
    }

    const client = new MongoClient(uri, {
      serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
      },
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });

    await client.connect();
    database = client.db(dbName);
    console.log("Connected successfully to MongoDB");
    return database;
  } catch (error) {
    console.error("Error connecting to database:", error);
    throw error;
  }
}

app.listen(port, (err) => {
  if (err) {
    console.error("Failed to start server:", err.message)

    process.exit(1)
  }

  console.log(`Server is running on http://localhost:${port}`)
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

// ... existing code ...

// Endpoint to check homeowners with Almost Due or Delinquent status
app.get("/api/check-homeowners-due", requireAuth, async (req, res) => {
  try {
    console.log("API Call: /api/check-homeowners-due");
    console.log("Session:", req.session);
    console.log("Query:", req.query);

    const client = await connectToDatabase();
    const db = client.db("ASC");
    const homeownersCollection = db.collection("homeowners");

    // Construct query for Almost Due or Delinquent status
    const query = {
      PStatus: { $in: ["Almost Due", "Delinquent"] }
    };

    console.log("Final query:", JSON.stringify(query));

    // Fetch homeowners with the specified status
    const homeowners = await homeownersCollection.find(query).toArray();
    console.log(`Found ${homeowners.length} homeowners with Almost Due or Delinquent status`);

    // Transform the data to include calculated fields
    const transformedHomeowners = homeowners.map(homeowner => {
      const lastPaymentDate = homeowner.lastPaymentDate ? new Date(homeowner.lastPaymentDate) : null;
      const daysSincePayment = lastPaymentDate ? Math.floor((new Date() - lastPaymentDate) / (1000 * 60 * 60 * 24)) : null;
      const delinquentSince = homeowner.delinquentSince ? new Date(homeowner.delinquentSince) : null;
        
      return {
        ...homeowner,
        daysSincePayment,
        delinquentSince: delinquentSince ? delinquentSince.toISOString() : null,
        lastPaymentDate: lastPaymentDate ? lastPaymentDate.toISOString() : null
      };
    });

    res.json({ data: transformedHomeowners });
  } catch (error) {
    console.error("Error in /api/check-homeowners-due:", error);
    res.status(500).json({ error: "Failed to fetch homeowners" });
  }
});

// ... existing code ...
app.post("/api/admin/create-homeowner-account", async (req, res) => {
  try {
    const db = await connectToDatabase();
    const homeownersCollection = db.collection("homeowners");
    const accCollection = db.collection("acc");

    const generateNewPasswords = req.body.generateNewPasswords;
    const homeowners = await homeownersCollection.find({}).toArray();

    const createdAccounts = [];

    for (const homeowner of homeowners) {
      const { firstName, lastName, Address } = homeowner;

      const block = Address?.Block?.$numberInt || Address?.Block;
      const lot = Address?.Lot?.$numberInt || Address?.Lot;
      const phase = Address?.Phase?.$numberInt || Address?.Phase;

      if (!firstName || !lastName || !block || !lot || !phase) continue;

      // Standardized username: lastname + firstname initial + block + lot + phase
      const username = `${lastName}${firstName.charAt(0)}${block}${lot}${phase}`;
      const password = `ASC${block}${lot}${phase}2025!`;

      const existingUser = await accCollection.findOne({ username });

      if (existingUser && !generateNewPasswords) continue;

      const hashedPassword = await bcrypt.hash(password, 10);

      if (!existingUser) {
        await accCollection.insertOne({
          username,
          password: hashedPassword,
          role: "homeowner",
          isHomeowner: "true",
          createdAt: new Date(),
        });
        // Update the homeowner document to include the username
        await homeownersCollection.updateOne(
          { _id: homeowner._id },
          { $set: { username } }
        );
        createdAccounts.push({
          success: true,
          homeowner: { firstName, lastName, username },
          password,
        });
      } else if (generateNewPasswords) {
        await accCollection.updateOne(
          { username },
          {
            $set: {
              password: hashedPassword,
              updatedAt: new Date(),
            },
          }
        );
        // Ensure the username is set in the homeowner document as well
        await homeownersCollection.updateOne(
          { _id: homeowner._id },
          { $set: { username } }
        );
        createdAccounts.push({
          success: true,
          homeowner: { firstName, lastName, username },
          password,
        });
      }
    }
    
    res.json({
      success: true,
      message: `${createdAccounts.length} accounts created.`,
      data: createdAccounts,
    });
  } catch (err) {
    console.error("Error creating accounts:", err);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// ... existing code ...

// ... existing code ...

app.use("/images", express.static(path.join(__dirname, "images")))

app.use("/CSS", express.static(path.join(__dirname, "CSS")))

app.use(express.static(path.join(__dirname)));
app.use("/Webpages", express.static(path.join(__dirname, "Webpages")));

// Catch-all route LAST
app.get("*", (req, res) => {
  if (req.headers.accept?.includes("application/json")) {
    return res.status(404).json({ success: false, message: "API endpoint not found" });
  }
  res.sendFile(path.join(__dirname, "Webpages", "login.html"));
});

app.get('/api/monthly-payments-summary', async (req, res) => {
  try {
    const payments = await db.collection('monthlypayments').find({}, {
      projection: {
        amount: 1,
        paymentMethod: 1,
        receiptImage: 1,
        status: 1,
        timestamp: 1,
        approvedAt: 1,
        approvedBy: 1,
        username: 1
      }
    }).toArray();
    res.json({ success: true, payments });
  } catch (error) {
    console.error('Error fetching monthly payments summary:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch monthly payments summary' });
  }
});


