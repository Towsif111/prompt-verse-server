const dns = require("node:dns");
dns.setServers(["8.8.8.8", "8.8.4.4"])


const express = require('express');
const cors = require('cors');
const app = express()
const port = 5000
require('dotenv').config();

app.use(cors());
app.use(express.json());

const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');

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
    const usersCollection = db.collection("users");

    const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret';
    const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
    const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

    
    function generateToken(user) {
      const payload = { id: user._id, email: user.email, role: user.role || 'User' };
      return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
    }

 
    function verifyToken(req, res, next) {
      const authHeader = req.headers.authorization;
      if (!authHeader) return res.status(401).json({ message: 'Missing authorization header' });
      const token = authHeader.split(' ')[1];
      if (!token) return res.status(401).json({ message: 'Invalid authorization header' });
      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
      } catch (err) {
        return res.status(401).json({ message: 'Invalid or expired token' });
      }
    }

  
    app.post('/auth/register', async (req, res) => {
      const { name, email, photoURL, password } = req.body;
      if (!email || !password || !name) return res.status(400).json({ message: 'Name, email and password are required' });
      const existing = await usersCollection.findOne({ email });
      if (existing) return res.status(409).json({ message: 'User already exists' });
      const hashed = await bcrypt.hash(password, 10);
      const newUser = {
        name,
        email,
        photoURL: photoURL || null,
        password: hashed,
        role: 'User',
        subscription: 'Free',
        createdAt: new Date()
      };
      const result = await usersCollection.insertOne(newUser);
      const user = await usersCollection.findOne({ _id: result.insertedId });
      const token = generateToken(user);
      res.status(201).json({ token, user: { id: user._id, name: user.name, email: user.email, role: user.role } });
    });

    
    app.post('/auth/login', async (req, res) => {
      const { email, password } = req.body;
      if (!email || !password) return res.status(400).json({ message: 'Email and password required' });
      const user = await usersCollection.findOne({ email });
      if (!user) return res.status(401).json({ message: 'Invalid credentials' });
      const match = await bcrypt.compare(password, user.password || '');
      if (!match) return res.status(401).json({ message: 'Invalid credentials' });
      const token = generateToken(user);
      res.json({ token, user: { id: user._id, name: user.name, email: user.email, role: user.role } });
    });

    
    app.post('/auth/google', async (req, res) => {
      const { idToken } = req.body;
      if (!idToken) return res.status(400).json({ message: 'idToken required' });
      let ticket;
      try {
        ticket = await googleClient.verifyIdToken({ idToken, audience: GOOGLE_CLIENT_ID });
      } catch (err) {
        return res.status(400).json({ message: 'Invalid Google ID token', error: err.message });
      }
      const payload = ticket.getPayload();
      const email = payload.email;
      let user = await usersCollection.findOne({ email });
      if (!user) {
        const newUser = {
          name: payload.name || 'Google User',
          email,
          photoURL: payload.picture || null,
          role: 'User',
          subscription: 'Free',
          createdAt: new Date()
        };
        const result = await usersCollection.insertOne(newUser);
        user = await usersCollection.findOne({ _id: result.insertedId });
      }
      const token = generateToken(user);
      res.json({ token, user: { id: user._id, name: user.name, email: user.email, role: user.role } });
    });

    
    app.get('/auth/me', verifyToken, async (req, res) => {
      const user = await usersCollection.findOne({ _id: new ObjectId(req.user.id) });
      if (!user) return res.status(404).json({ message: 'User not found' });
      res.json({ id: user._id, name: user.name, email: user.email, role: user.role, subscription: user.subscription });
    });

    app.get("/all-promts", async (req, res) => {
      const count = await promptCollection.countDocuments();
      console.log("Documents found:", count);

      const result = await promptCollection.find().toArray();

      console.log(result);

      res.json(result);
    });

    app.get("/all-promts/:id", verifyToken, async (req, res) => {
      const { id } = req.params;
      const result = await roomCollection.findOne({
        _id: new ObjectId(id),
      });

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