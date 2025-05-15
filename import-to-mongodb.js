import { MongoClient } from 'mongodb';
import fs from 'fs';

// Load the transformed data
const loadData = () => {
  try {
    const data = fs.readFileSync('transformed_data.json', 'utf8');
    return JSON.parse(data);
  } catch (error) {
    console.error('Error loading data:', error.message);
    process.exit(1);
  }
};

// Connect to MongoDB and import data
const importToMongoDB = async () => {
  // Replace with your MongoDB Atlas connection string
  const uri = 'mongodb+srv://ethan:Edj1026@avidadb.upica.mongodb.net/?retryWrites=true&w=majority&appName=avidadb';
  const client = new MongoClient(uri);

  try {
    await client.connect();
    console.log('Connected to MongoDB Atlas');

    const database = client.db('avidadb');
    const collection = database.collection('address');

    // Load the data
    const data = loadData();
    console.log(`Loaded ${data.length} records from file`);

    // Option 1: Insert all documents at once (faster but less error control)
    const result = await collection.insertMany(data);
    console.log(`${result.insertedCount} documents were inserted`);

    /* 
    // Option 2: Insert documents in batches (better for very large datasets)
    const batchSize = 1000;
    let inserted = 0;
    
    for (let i = 0; i < data.length; i += batchSize) {
      const batch = data.slice(i, i + batchSize);
      const result = await collection.insertMany(batch);
      inserted += result.insertedCount;
      console.log(`Progress: ${inserted}/${data.length} documents inserted`);
    }
    console.log(`Total: ${inserted} documents were inserted`);
    */

  } catch (error) {
    console.error('Error importing data:', error.message);
  } finally {
    await client.close();
    console.log('MongoDB connection closed');
  }
};

// Run the import function
importToMongoDB().catch(console.error);