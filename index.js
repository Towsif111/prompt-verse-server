const dns = require("node:dns");
dns.setServers(["8.8.8.8","8.8.4.4"])


const express = require('express');
const cors = require('cors');
const app = express()
const port = 5000
require('dotenv').config();

app.use(cors());
app.use(express.json());

const { MongoClient, ServerApiVersion } = require('mongodb');

app.get('/', (req, res) => {
  res.send('Hello World!')
})


const uri = process.env.MONGO_DB_URI;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function run() {
  try {
    await client.connect();

    const db = client.db("promtverse_db");
    const promptCollection = db.collection("promts");

    app.get("/all-promts", async (req, res) => {
  const count = await promptCollection.countDocuments();
  console.log("Documents found:", count);

  const result = await promptCollection.find().toArray();

  console.log(result);

  res.json(result);
});
    






    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");

    app.listen(port, () => {
      console.log(`Example app listening on port ${port}`)
    })
  } finally {
    // Connection kept alive for incoming requests
  }
}

// Graceful shutdown: close MongoDB connection on exit
process.on('SIGINT', async () => {
  console.log('Shutting down...');
  await client.close();
  process.exit(0);
});

run().catch(console.dir);