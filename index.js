const app = require("./server")

const port = process.env.PORT || 3000

// Single app.listen call
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`)
  console.log(`Debug endpoint: http://localhost:${port}/debug`)
})

