const app = require("./server")

const port = process.env.PORT || 3000

// Remove any other app.listen calls from server.js
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`)
  console.log(`Debug endpoint: http://localhost:${port}/debug`)
  console.log(`DB test endpoint: http://localhost:${port}/api/test-db`)
})

