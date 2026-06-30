const dns = require("node:dns");
dns.setServers(["8.8.8.8", "8.8.4.4"])


const express = require('express');
const cors = require('cors');
const app = express()
const port = 5000
require('dotenv').config();

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

    // RBAC middleware: require specific role(s)
    function requireRole(...roles) {
      return (req, res, next) => {
        if (!req.user) {
          return res.status(401).json({ message: 'Authentication required' });
        }
        if (!roles.includes(req.user.role)) {
          return res.status(403).json({ message: `Access denied. Required role: ${roles.join(' or ')}` });
        }
        next();
      };
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

    app.get("/all-promts/:id", async (req, res) => {
      const { id } = req.params;
      try {
        const result = await promptCollection.findOne({
          _id: new ObjectId(id),
        });
        if (!result) return res.status(404).json({ message: 'Prompt not found' });
        res.json(result);
      } catch (err) {
        res.status(400).json({ message: 'Invalid ID format', error: err.message });
      }
    });

    // ===== REVIEWS =====

    // Get reviews for a prompt
    app.get("/api/prompts/:id/reviews", async (req, res) => {
      const { id } = req.params;
      try {
        const reviewsCollection = db.collection("reviews");
        const reviews = await reviewsCollection.find({ promptId: id }).sort({ createdAt: -1 }).toArray();
        res.json(reviews);
      } catch (err) {
        res.status(500).json({ error: err.message });
      }
    });

    // Submit a review
    app.post("/api/reviews", async (req, res) => {
      const { promptId, userEmail, userName, rating, comment } = req.body;
      if (!promptId || !userEmail || !rating) {
        return res.status(400).json({ error: "promptId, userEmail, and rating are required" });
      }
      try {
        const reviewsCollection = db.collection("reviews");
        // Check if user already reviewed this prompt
        const existing = await reviewsCollection.findOne({ promptId, userEmail });
        if (existing) {
          return res.status(409).json({ error: "You have already reviewed this prompt" });
        }
        const review = {
          promptId,
          userEmail,
          userName: userName || "Anonymous",
          rating,
          comment: comment || "",
          createdAt: new Date(),
        };
        const result = await reviewsCollection.insertOne(review);
        res.status(201).json({ ...review, _id: result.insertedId });
      } catch (err) {
        res.status(500).json({ error: err.message });
      }
    });

    // Get user's reviews
    app.get("/api/my-reviews/:email", async (req, res) => {
      const { email } = req.params;
      try {
        const reviewsCollection = db.collection("reviews");
        const reviews = await reviewsCollection.find({ userEmail: email }).sort({ createdAt: -1 }).toArray();
        res.json(reviews);
      } catch (err) {
        res.status(500).json({ error: err.message });
      }
    });

    // ===== BOOKMARKS =====

    // Get all bookmarks for a user
    app.get("/api/bookmarks/:email", async (req, res) => {
      const { email } = req.params;
      try {
        const bookmarksCollection = db.collection("bookmarks");
        const bookmarkEntries = await bookmarksCollection.find({ userEmail: email }).toArray();
        const promptIds = bookmarkEntries.map(b => b.promptId);
        const prompts = await promptCollection.find({ _id: { $in: promptIds.map(id => { try { return new ObjectId(id); } catch { return id; } }) } }).toArray();
        res.json(prompts);
      } catch (err) {
        res.status(500).json({ error: err.message });
      }
    });

    // Check bookmark status
    app.get("/api/bookmarks/:email/:promptId", async (req, res) => {
      const { email, promptId } = req.params;
      try {
        const bookmarksCollection = db.collection("bookmarks");
        const bookmark = await bookmarksCollection.findOne({ userEmail: email, promptId });
        res.json({ bookmarked: !!bookmark });
      } catch (err) {
        res.status(500).json({ error: err.message });
      }
    });

    // Toggle bookmark
    app.post("/api/bookmarks/toggle", async (req, res) => {
      const { userEmail, promptId } = req.body;
      if (!userEmail || !promptId) {
        return res.status(400).json({ error: "userEmail and promptId are required" });
      }
      try {
        const bookmarksCollection = db.collection("bookmarks");
        const existing = await bookmarksCollection.findOne({ userEmail, promptId });
        if (existing) {
          await bookmarksCollection.deleteOne({ userEmail, promptId });
          res.json({ bookmarked: false });
        } else {
          await bookmarksCollection.insertOne({ userEmail, promptId, createdAt: new Date() });
          res.json({ bookmarked: true });
        }
      } catch (err) {
        res.status(500).json({ error: err.message });
      }
    });

    // ===== PROMPTS CRUD =====

    // Create a new prompt
    app.post("/api/prompts", async (req, res) => {
      const { title, description, prompt, category, aiTool, tags, difficulty, thumbnail, visibility, creatorEmail, creatorName } = req.body;
      if (!title || !description || !prompt) {
        return res.status(400).json({ error: "title, description, and prompt are required" });
      }
      try {
        const newPrompt = {
          title,
          description,
          prompt,
          category: category || "Other",
          aiTool: aiTool || "Other",
          tags: tags || [],
          difficulty: difficulty || "Beginner",
          thumbnail: thumbnail || "",
          visibility: visibility || "Public",
          creatorEmail: creatorEmail || "",
          creatorName: creatorName || "",
          status: "pending",
          copyCount: 0,
          rating: 0,
          featured: false,
          createdAt: new Date(),
        };
        const result = await promptCollection.insertOne(newPrompt);
        res.status(201).json({ ...newPrompt, _id: result.insertedId });
      } catch (err) {
        res.status(500).json({ error: err.message });
      }
    });

    // Get prompts by creator email
    app.get("/api/my-prompts/:email", async (req, res) => {
      const { email } = req.params;
      try {
        const prompts = await promptCollection.find({ creatorEmail: email }).sort({ createdAt: -1 }).toArray();
        res.json(prompts);
      } catch (err) {
        res.status(500).json({ error: err.message });
      }
    });

    // Delete a prompt
    app.delete("/api/prompts/:id", async (req, res) => {
      const { id } = req.params;
      try {
        await promptCollection.deleteOne({ _id: new ObjectId(id) });
        res.json({ message: "Prompt deleted" });
      } catch (err) {
        res.status(500).json({ error: err.message });
      }
    });

    // Increment copy count
    app.post("/api/prompts/:id/copy", async (req, res) => {
      const { id } = req.params;
      try {
        await promptCollection.updateOne(
          { _id: new ObjectId(id) },
          { $inc: { copyCount: 1 } }
        );
        res.json({ message: "Copy count incremented" });
      } catch (err) {
        res.status(500).json({ error: err.message });
      }
    });

    // ===== REPORTS =====

    // Submit a report
    app.post("/api/reports", async (req, res) => {
      const { promptId, userEmail, reason, description } = req.body;
      if (!promptId || !userEmail || !reason) {
        return res.status(400).json({ error: "promptId, userEmail, and reason are required" });
      }
      try {
        const reportsCollection = db.collection("reports");
        const report = {
          promptId,
          reportedBy: userEmail,
          reason,
          description: description || "",
          status: "pending",
          createdAt: new Date(),
        };
        const result = await reportsCollection.insertOne(report);
        res.status(201).json({ ...report, _id: result.insertedId });
      } catch (err) {
        res.status(500).json({ error: err.message });
      }
    });

    // Get all reports (admin)
    app.get("/api/reports", verifyToken, requireRole("Admin"), async (req, res) => {
      try {
        const reportsCollection = db.collection("reports");
        const reports = await reportsCollection.find().sort({ createdAt: -1 }).toArray();
        // Attach prompt title to each report
        const reportsWithPrompts = await Promise.all(reports.map(async (report) => {
          try {
            const prompt = await promptCollection.findOne({ _id: new ObjectId(report.promptId) });
            return { ...report, prompt: prompt ? { title: prompt.title } : null };
          } catch {
            return { ...report, prompt: null };
          }
        }));
        res.json(reportsWithPrompts);
      } catch (err) {
        res.status(500).json({ error: err.message });
      }
    });

    // ===== CREATOR ANALYTICS =====

    app.get("/api/creator/analytics", verifyToken, requireRole("Admin", "Creator"), async (req, res) => {
      const userEmail = req.user.email;
      try {
        const myPrompts = await promptCollection.find({ creatorEmail: userEmail }).toArray();
        const totalPrompts = myPrompts.length;
        const totalCopies = myPrompts.reduce((sum, p) => sum + (p.copyCount || 0), 0);

        // Count bookmarks across all prompts
        const bookmarksCollection = db.collection("bookmarks");
        const promptIds = myPrompts.map(p => p._id.toString());
        const totalBookmarks = await bookmarksCollection.countDocuments({ promptId: { $in: promptIds } });

        // Monthly growth
        const monthlyGrowth = await promptCollection.aggregate([
          { $match: { creatorEmail: userEmail } },
          {
            $group: {
              _id: {
                $dateToString: { format: "%Y-%m", date: "$createdAt" }
              },
              count: { $sum: 1 }
            }
          },
          { $sort: { _id: 1 } }
        ]).toArray();

        res.json({
          totalPrompts,
          totalCopies,
          totalBookmarks,
          promptCopies: myPrompts.map(p => ({ title: p.title, copyCount: p.copyCount, createdAt: p.createdAt })),
          monthlyGrowth,
        });
      } catch (err) {
        res.status(500).json({ error: err.message });
      }
    });

    // ===== ADMIN ANALYTICS =====

    app.get("/api/admin/analytics", verifyToken, requireRole("Admin"), async (req, res) => {
      try {
        const totalUsers = await usersCollection.countDocuments();
        const totalPrompts = await promptCollection.countDocuments();
        const reviewsCollection = db.collection("reviews");
        const totalReviews = await reviewsCollection.countDocuments();

        const allPrompts = await promptCollection.find().toArray();
        const totalCopies = allPrompts.reduce((sum, p) => sum + (p.copyCount || 0), 0);

        const monthlyGrowth = await promptCollection.aggregate([
          {
            $group: {
              _id: {
                $dateToString: { format: "%Y-%m", date: "$createdAt" }
              },
              count: { $sum: 1 }
            }
          },
          { $sort: { _id: 1 } }
        ]).toArray();

        res.json({ totalUsers, totalPrompts, totalCopies, totalReviews, monthlyGrowth });
      } catch (err) {
        res.status(500).json({ error: err.message });
      }
    });

    // ===== ADMIN USERS =====

    app.get("/api/admin/users", verifyToken, requireRole("Admin"), async (req, res) => {
      try {
        const users = await usersCollection.find().toArray();
        const usersWithPromptCounts = await Promise.all(users.map(async (user) => {
          const count = await promptCollection.countDocuments({ creatorEmail: user.email });
          return { ...user, password: undefined, totalPrompts: count };
        }));
        res.json(usersWithPromptCounts);
      } catch (err) {
        res.status(500).json({ error: err.message });
      }
    });

    app.put("/api/admin/users/:id/role", verifyToken, requireRole("Admin"), async (req, res) => {
      const { id } = req.params;
      const { role } = req.body;
      if (!role) return res.status(400).json({ error: "role is required" });
      try {
        await usersCollection.updateOne({ _id: new ObjectId(id) }, { $set: { role } });
        res.json({ message: "Role updated" });
      } catch (err) {
        res.status(500).json({ error: err.message });
      }
    });

    app.delete("/api/admin/users/:id", verifyToken, requireRole("Admin"), async (req, res) => {
      const { id } = req.params;
      try {
        const user = await usersCollection.findOne({ _id: new ObjectId(id) });
        if (user) {
          await promptCollection.deleteMany({ creatorEmail: user.email });
          const bookmarksCollection = db.collection("bookmarks");
          await bookmarksCollection.deleteMany({ userEmail: user.email });
        }
        await usersCollection.deleteOne({ _id: new ObjectId(id) });
        res.json({ message: "User deleted" });
      } catch (err) {
        res.status(500).json({ error: err.message });
      }
    });

    // ===== ADMIN PROMPTS =====

    app.get("/api/admin/prompts", verifyToken, requireRole("Admin"), async (req, res) => {
      try {
        const prompts = await promptCollection.find().sort({ createdAt: -1 }).toArray();
        res.json(prompts);
      } catch (err) {
        res.status(500).json({ error: err.message });
      }
    });

    app.put("/api/admin/prompts/:id/status", verifyToken, requireRole("Admin"), async (req, res) => {
      const { id } = req.params;
      const { status, rejectionFeedback, featured } = req.body;
      try {
        const updateFields = {};
        if (status) updateFields.status = status;
        if (rejectionFeedback) updateFields.rejectionFeedback = rejectionFeedback;
        if (featured !== undefined) updateFields.featured = featured;
        await promptCollection.updateOne({ _id: new ObjectId(id) }, { $set: updateFields });
        res.json({ message: "Prompt updated" });
      } catch (err) {
        res.status(500).json({ error: err.message });
      }
    });

    app.delete("/api/admin/prompts/:id", verifyToken, requireRole("Admin"), async (req, res) => {
      const { id } = req.params;
      try {
        await promptCollection.deleteOne({ _id: new ObjectId(id) });
        res.json({ message: "Prompt deleted" });
      } catch (err) {
        res.status(500).json({ error: err.message });
      }
    });

    // ===== ADMIN REPORTS =====

    app.put("/api/admin/reports/:id", verifyToken, requireRole("Admin"), async (req, res) => {
      const { id } = req.params;
      const { status } = req.body;
      try {
        const reportsCollection = db.collection("reports");
        await reportsCollection.updateOne({ _id: new ObjectId(id) }, { $set: { status } });
        res.json({ message: "Report updated" });
      } catch (err) {
        res.status(500).json({ error: err.message });
      }
    });

    app.delete("/api/admin/reports/:id", verifyToken, requireRole("Admin"), async (req, res) => {
      const { id } = req.params;
      try {
        const reportsCollection = db.collection("reports");
        await reportsCollection.deleteOne({ _id: new ObjectId(id) });
        res.json({ message: "Report deleted" });
      } catch (err) {
        res.status(500).json({ error: err.message });
      }
    });

    // ===== PAYMENTS =====

    app.get("/api/payments", verifyToken, requireRole("Admin"), async (req, res) => {
      try {
        const paymentsCollection = db.collection("payments");
        const payments = await paymentsCollection.find().sort({ createdAt: -1 }).toArray();
        res.json(payments);
      } catch (err) {
        res.status(500).json({ error: err.message });
      }
    });

    // Create Stripe checkout session
    app.post("/api/create-checkout-session", async (req, res) => {
      const { email, userId } = req.body;
      if (!email) return res.status(400).json({ error: "Email is required" });

      try {
        const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
        const session = await stripe.checkout.sessions.create({
          payment_method_types: ['card'],
          line_items: [{
            price_data: {
              currency: 'usd',
              product_data: { name: 'PromptVerse Premium Subscription' },
              unit_amount: 500, // $5.00
            },
            quantity: 1,
          }],
          mode: 'payment',
          success_url: `${req.headers.origin || 'http://localhost:3000'}/payment/success?session_id={CHECKOUT_SESSION_ID}`,
          cancel_url: `${req.headers.origin || 'http://localhost:3000'}/payment`,
          customer_email: email,
          metadata: { email, userId: userId || '' },
        });
        res.json({ url: session.url });
      } catch (err) {
        console.error("Stripe error:", err.message);
        res.status(500).json({ error: "Failed to create checkout session: " + err.message });
      }
    });

    // Verify payment and update user subscription
    app.get("/api/verify-payment/:sessionId", async (req, res) => {
      const { sessionId } = req.params;
      try {
        const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
        const stripeSession = await stripe.checkout.sessions.retrieve(sessionId);

        if (stripeSession.payment_status === 'paid') {
          const email = stripeSession.metadata?.email;
          const betterAuthUserId = stripeSession.metadata?.userId;
          if (email) {
            // 1. Update Express users collection
            await usersCollection.updateOne(
              { email },
              { $set: { subscription: 'Premium' } }
            );

            // 2. Also update Better Auth user collection so the UI reflects Premium status
            const authDbName = process.env.AUTH_DB_NAME || 'better-auth';
            try {
              const authDb = client.db(authDbName);
              const authUsersCollection = authDb.collection("user");
              // Try by Better Auth user ID first, fall back to email
              if (betterAuthUserId) {
                await authUsersCollection.updateOne(
                  { id: betterAuthUserId },
                  { $set: { subscription: 'Premium' } }
                );
              }
              // Also update by email as a fallback
              await authUsersCollection.updateOne(
                { email },
                { $set: { subscription: 'Premium' } }
              );
            } catch (authErr) {
              console.error("Failed to update Better Auth user:", authErr.message);
              // Non-critical — Express user was updated
            }

            // Record payment
            const paymentsCollection = db.collection("payments");
            await paymentsCollection.insertOne({
              email,
              amount: 5.00,
              status: 'completed',
              stripeSessionId: sessionId,
              createdAt: new Date(),
            });
          }
          res.json({ verified: true });
        } else {
          res.json({ verified: false });
        }
      } catch (err) {
        console.error("Verify payment error:", err.message);
        res.status(500).json({ verified: false, error: err.message });
      }
    });

    // ===== SEED DEMO USERS =====

    app.post('/auth/seed-demo', async (req, res) => {
      const DEMO_USERS = [
        {
          name: "Admin Demo",
          email: "admin@demo.com",
          password: "Demo@123",
          role: "Admin",
          subscription: "Premium",
          photoURL: null,
        },
        {
          name: "Creator Demo",
          email: "creator@demo.com",
          password: "Demo@123",
          role: "Creator",
          subscription: "Premium",
          photoURL: null,
        },
        {
          name: "User Demo",
          email: "user@demo.com",
          password: "Demo@123",
          role: "User",
          subscription: "Free",
          photoURL: null,
        },
      ];

      try {
        const results = [];
        for (const demo of DEMO_USERS) {
          const existing = await usersCollection.findOne({ email: demo.email });
          if (existing) {
            results.push({ email: demo.email, status: 'already exists' });
            continue;
          }
          const hashed = await bcrypt.hash(demo.password, 10);
          const newUser = {
            name: demo.name,
            email: demo.email,
            password: hashed,
            role: demo.role,
            subscription: demo.subscription,
            photoURL: demo.photoURL,
            createdAt: new Date()
          };
          await usersCollection.insertOne(newUser);
          results.push({ email: demo.email, status: 'created' });
        }
        res.json({ message: 'Demo users seeded successfully', results });
      } catch (err) {
        res.status(500).json({ message: 'Failed to seed demo users', error: err.message });
      }
    });

    // Send a ping to confirm a successful connection
    //await client.db("admin").command({ ping: 1 });
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