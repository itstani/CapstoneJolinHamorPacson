import fs from "fs"

function checkDeploymentReadiness() {
  const requiredFiles = ["package.json", "server.js"]
  const requiredDirs = ["Webpages"]
  const errors = []
  const warnings = []

  console.log("🔍 Checking deployment readiness...\n")

  // Check required files
  console.log("Checking required files:")
  requiredFiles.forEach((file) => {
    if (!fs.existsSync(file)) {
      errors.push(`Missing required file: ${file}`)
      console.log(`❌ ${file} not found`)
    } else {
      console.log(`✅ ${file} found`)
    }
  })

  // Check required directories
  console.log("\nChecking required directories:")
  requiredDirs.forEach((dir) => {
    if (!fs.existsSync(dir)) {
      errors.push(`Missing required directory: ${dir}`)
      console.log(`❌ ${dir}/ not found`)
    } else {
      console.log(`✅ ${dir}/ found`)
    }
  })

  // Check package.json configuration
  try {
    const packageJson = JSON.parse(fs.readFileSync("package.json", "utf8"))
    console.log("\nChecking package.json configuration:")

    if (!packageJson.scripts?.start) {
      errors.push("Missing start script in package.json")
      console.log("❌ No start script defined")
    } else {
      console.log("✅ Start script found")
    }

    if (!packageJson.main) {
      warnings.push("No main field in package.json")
      console.log("⚠️ No main field defined")
    } else {
      console.log("✅ Main field found")
    }
  } catch (error) {
    errors.push("Invalid package.json")
    console.log("❌ Invalid package.json")
  }

  // Summary
  console.log("\n📋 Summary:")
  if (errors.length > 0) {
    console.log("\nErrors found:")
    errors.forEach((error) => console.log(`❌ ${error}`))
  }
  if (warnings.length > 0) {
    console.log("\nWarnings found:")
    warnings.forEach((warning) => console.log(`⚠️ ${warning}`))
  }
  if (errors.length === 0 && warnings.length === 0) {
    console.log("✅ Project is ready for deployment!")
  }
}

checkDeploymentReadiness()

