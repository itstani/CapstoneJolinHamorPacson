// This file is only used for local development
// Vercel will use the server.js file directly
const app = require("./server")

const port = process.env.PORT || 3000

// Only listen when running locally, not on Vercel
if (process.env.NODE_ENV !== "production") {
  app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`)
    console.log(`Debug endpoint: http://localhost:${port}/debug`)
    console.log(`DB test endpoint: http://localhost:${port}/api/test-db`)
  })
}

