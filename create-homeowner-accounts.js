const bcrypt = require("bcryptjs")
const { connectToDatabase } = require("./db")
const { ObjectId } = require("mongodb") // Import ObjectId

// Function to create accounts for homeowners who don't have one
async function createHomeownerAccounts(homeowners) {
  const results = []

  for (const homeowner of homeowners) {
    try {
      const db = await connectToDatabase()
      // Check if account already exists
      const existingAccount = await db.collection("acc").findOne({ email: homeowner.email })

      if (existingAccount) {
        // Account already exists
        results.push({
          homeowner,
          success: false,
          message: "Account already exists",
          password: null,
        })
        continue
      }

      // Extract block, lot, and phase numbers from address
      let blockNumber, lotNumber, phaseNumber;
      
      if (typeof homeowner.Address === 'object') {
        // New structure
        blockNumber = homeowner.Address.Block?.$numberInt || homeowner.Address.Block;
        lotNumber = homeowner.Address.Lot?.$numberInt || homeowner.Address.Lot;
        phaseNumber = homeowner.Address.Phase?.$numberInt || homeowner.Address.Phase;
      } else {
        // Old structure - try to extract from string
        const blockMatch = homeowner.Address?.match(/Block\s+(\d+)/i);
        const lotMatch = homeowner.Address?.match(/Lot\s+(\d+)/i);
        const phaseMatch = homeowner.Address?.match(/Phase\s+(\d+)/i);
        
        blockNumber = blockMatch ? blockMatch[1] : null;
        lotNumber = lotMatch ? lotMatch[1] : null;
        phaseNumber = phaseMatch ? phaseMatch[1] : null;
      }

      if (!blockNumber || !lotNumber || !phaseNumber) {
        results.push({
          homeowner,
          success: false,
          message: "Address does not contain valid Block, Lot, and Phase numbers",
          password: null,
        })
        continue
      }

      // Generate username: first initial + last initial + block + lot + phase
      const firstName = homeowner.firstName || ""
      const lastName = homeowner.lastName || ""
      const firstInitial = firstName.charAt(0).toUpperCase()
      const lastInitial = lastName.charAt(0).toUpperCase()
      const username = `${firstInitial}${lastInitial}${blockNumber}${lotNumber}${phaseNumber}`

      // Generate password: ASC + block + lot + 2025!
      const password = `ASC${blockNumber}${lotNumber}2025!`
      const hashedPassword = await bcrypt.hash(password, 10)

      // Ensure email has a domain
      let email = homeowner.email
      if (!email || !email.includes("@")) {
        email = `${username.toLowerCase()}@asc.system`
      }

      // Create the account
      const account = {
        username: username,
        email: email,
        password: hashedPassword,
        role: "homeowner",
        isHomeowner: "true",
        createdAt: new Date(),
      }

      await db.collection("acc").insertOne(account)

      results.push({
        homeowner,
        success: true,
        message: "Account created successfully",
        password,
      })
    } catch (error) {
      console.error(`Error creating account for ${homeowner.email}:`, error)
      results.push({
        homeowner,
        success: false,
        message: "Error creating account",
        password: null,
      })
    }
  }

  return results
}

// Export the function
module.exports = {
  createHomeownerAccounts,
  handleCreateAccounts: async (req, res) => {
    try {
      const db = await connectToDatabase()
      const homeownersCollection = db.collection("homeowners")
      const homeowners = await homeownersCollection.find({}).toArray()
      const results = await createHomeownerAccounts(homeowners)
      const createdCount = results.filter((r) => r.success).length
      const failedCount = results.filter((r) => !r.success).length

      res.json({
        success: true,
        message: `Created ${createdCount} accounts, skipped ${failedCount} accounts`,
        data: results,
      })
    } catch (error) {
      console.error("Error in create accounts handler:", error)
      res.status(500).json({
        success: false,
        message: "Failed to create homeowner accounts",
        error: error.message,
      })
    }
  },
  handleGetHomeownerCredentials: async (req, res) => {
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
        let blockNumber, lotNumber;
        
        if (typeof homeowner.Address === 'object') {
          blockNumber = homeowner.Address.Block?.$numberInt || homeowner.Address.Block;
          lotNumber = homeowner.Address.Lot?.$numberInt || homeowner.Address.Lot;
        } else {
          const blockMatch = homeowner.Address.match(/Block\s+(\d+)/i);
          const lotMatch = homeowner.Address.match(/Lot\s+(\d+)/i);
          blockNumber = blockMatch ? blockMatch[1] : null;
          lotNumber = lotMatch ? lotMatch[1] : null;
        }

        if (blockNumber && lotNumber) {
          // Generate password in the format: ASC + block + lot + 2025!
          newPassword = `ASC${blockNumber}${lotNumber}2025!`

          // Hash the new password
          const hashedPassword = await bcrypt.hash(newPassword, 10)

          // Update the account with the new password
          await accCollection.updateOne({ _id: account._id }, { $set: { password: hashedPassword } })
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
  },
}
