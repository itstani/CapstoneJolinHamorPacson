// db.js
const { MongoClient } = require("mongodb");
const uri = process.env.MONGODB_URI;
const dbName = process.env.DB_NAME || "avidadb";

let cachedClient = null;
let cachedDb = null;

async function connectToDatabase() {
  if (cachedDb) {
    return cachedDb;
  }

  if (!uri) {
    throw new Error("MongoDB URI is not defined");
  }

  const client = new MongoClient(uri, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  });

  if (!cachedClient) {
    cachedClient = await client.connect();
  }

  const db = cachedClient.db(dbName);
  cachedDb = db;
  return db;
}

module.exports = { connectToDatabase };