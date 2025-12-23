// backend/index.js
require("dotenv").config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const upload = require("./upload");
const { sendEmail } = require("./email");
const { MongoClient, ObjectId } = require('mongodb');

const SALT_ROUNDS = 10;
const SECRET_KEY = process.env.SECRET_KEY || '9e7ae63e6d9e3654139277c630af4973';
const app = express();
const port =  process.env.PORT || 5500;

app.use(express.json());

const client = new MongoClient(process.env.MONGO_URI);
let db;

// Update CORS to accept frontend URL
const allowedOrigins = [
  'http://localhost:3000',
  'http://localhost:5500',
  'https://ntou-event-registration-system2-five.vercel.app'
];

app.use(cors({
  origin: function (origin, callback) {
    console.log("Incoming origin:", origin);
    console.log("Allowed origins:", allowedOrigins);

    if (!origin) return callback(null, true);

    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    return callback(new Error(`CORS blocked: ${origin}`), false);
  }
}));
// Connect to MongoDB
let cachedDb = null;
async function connectDB() {
  if (cachedDb) return cachedDb;

  const client = new MongoClient(process.env.MONGO_URI);
  await client.connect();
  cachedDb = client.db("eventRegistration");

  console.log("✅ MongoDB connected");
  return cachedDb;
}

// Wait for DB connection before starting server
connectDB().then(() => {
    app.listen(port, () => {
        console.log(`Server running at http://localhost:${port}`);
    });
}).catch(err => {
    console.error("❌ Could not start server:", err);
});

// ---------- Endpoint to get next incremental ID ----------
app.get('/nextId', async (req, res) => {
    try {
        const db = await connectDB();
        const result = await db.collection('counters').findOneAndUpdate(
            { _id: 'userId' },
            { $inc: { seq: 1 } },
            { returnDocument: 'after', upsert: true }
        );

        let nextId;
        if (result.value && typeof result.value.seq === 'number') {
            nextId = result.value.seq;
        } else {
            const doc = await db.collection('counters').findOne({ _id: 'userId' });
            nextId = doc.seq;
        }

        res.json({ nextId });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to get next ID' });
    }
});

// ---------- Register endpoint ----------
app.post('/register', async (req, res) => {
    try {
        const db = await connectDB();
        const { id, nickname, email_or_phone, password, occupation } = req.body;

        // Check if email or phone already exists
        const existingUser = await db.collection('users').findOne({ email: email_or_phone });
        if (existingUser) {
            return res.status(400).json({ error: 'Email already registered' });
        }

        // Get next user ID
        if (!id || !nickname || !email_or_phone || !password) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        const role = 'User';
        const created_at = new Date().toISOString().slice(0, 19).replace('T', ' ');

        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
        const newUser = {
            id,
            name: nickname,
            email: email_or_phone,
            password_hash: hashedPassword,
            role,
            occupation,
            created_at
        };

        const result = await db.collection('users').insertOne(newUser);

        console.log('User registered successfully:', result.insertedId);
        res.json({ message: 'Registration successful', id: result.insertedId });

    } catch (error) {
        console.error('Error during registration:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// -------------Sign In Endpoint-------------
app.post('/signin', async (req, res) => {
    try {
        const db = await connectDB();
        const { email_or_phone, password } = req.body;

        const user = await db.collection('users').findOne({ email: email_or_phone });
        if (!user) return res.status(404).json({ error: 'User not found' });

        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) return res.status(401).json({ error: 'Incorrect password' });

        // Create JWT token (valid for 1 hour)
        const token = jwt.sign(
            { email: user.email, name: user.name, id: user.id, role: user.role, occupation: user.occupation },
            SECRET_KEY,
            { expiresIn: '1h' }
        );

        res.json({ message: 'Sign In successful', token});
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ---------- Middleware to verify JWT token ----------
function verifyToken(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token provided' });

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).json({ error: 'Invalid or expired token' });
    }
}

// -------------Verify Old Password-------------
app.post('/users/verify-password', verifyToken, async (req, res) => {
    try {
        const db = await connectDB();
        const userId = req.user.id;
        const { oldPassword } = req.body;

        if (!oldPassword) {
            return res.status(400).json({ error: 'Old password is required' });
        }

        // Find user in DB
        const user = await db.collection('users').findOne({ id: parseInt(userId) });
        if (!user) return res.status(404).json({ error: 'User not found' });

        // Compare password
        const match = await bcrypt.compare(oldPassword, user.password_hash);
        if (!match) return res.status(401).json({ error: 'Old password is incorrect' });

        res.json({ message: 'Password verified' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to verify password' });
    }
});

// -------------Change Password Endpoint-------------
app.patch('/users/update-password', verifyToken, async (req, res) => {
    try {
        const db = await connectDB();
        const userId = req.user.id; // from JWT payload
        const { newPassword } = req.body;

        if (!newPassword) {
            return res.status(400).json({ error: 'New password is required' });
        }

        // Hash new password
        const hashedPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);

        // Update in DB
        const result = await db.collection('users').updateOne(
            { id: parseInt(userId) },
            { $set: { password_hash: hashedPassword } }
        );

        if (result.modifiedCount === 0) {
            return res.status(500).json({ error: 'Failed to update password' });
        }

        res.json({ message: 'Password updated successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to update password' });
    }
});

// ---------- Get User for User List ------------
app.get('/users', async (req, res) => {
    try{
        const db = await connectDB();
        const users = await db.collection('users').find().toArray();
        res.json(users);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

// ---------- Get ongoing events ----------
app.get('/events', async (req, res) => {
  try {
    const db = await connectDB();
    const todayEnd = new Date(); todayEnd.setHours(23,59,59,999);

    const events = await db.collection('events').aggregate([
      { $match: { $expr: { $gt: [{ $toDate: "$date" }, todayEnd] } } },
      { $lookup: { from: 'users', localField: 'createdBy', foreignField: 'id', as: 'owner' } },
      { $lookup: { from: 'applications', localField: 'id', foreignField: 'eventId', as: 'applications' } },
      { $addFields: {
          ownerEmail: { $ifNull: [{ $arrayElemAt: ['$owner.email',0] }, null] },
          participantCount: { $size: { $filter: { input:'$applications', as:'app', cond:{$eq:['$$app.status',1]} } } }
      }},
      { $project: { owner:0, applications:0 } }
    ]).toArray();

    res.json(events);
  } catch (err) {
    console.error("🔥 /events error:", err);
    res.status(500).json({ error: 'Failed to fetch events' });
  }
});

// ---------- Get events for management (filtered by owner for advanced users) ----------
app.get('/manage/events', verifyToken, async (req, res) => {
    try {
        const db = await connectDB();
        const userRole = req.user.role;
        const userId = req.user.id;
        
        let matchQuery = {};
        
        // Advanced users can only see their own events
        if (userRole === 'Advanced User') {
            matchQuery.createdBy = parseInt(userId);
        }
        // Administrators can see all events
        
        const events = await db.collection('events').aggregate([
            { $match: matchQuery },
            {
                $lookup: {
                    from: 'users',
                    localField: 'createdBy',
                    foreignField: 'id',
                    as: 'owner'
                }
            },
            {
                $lookup: {
                    from: 'applications',
                    localField: 'id',
                    foreignField: 'eventId',
                    as: 'applications'
                }
            },
            {
                $addFields: {
                    ownerEmail: {
                        $ifNull: [
                            { $arrayElemAt: ['$owner.email', 0] },
                            null
                        ]
                    },
                    participantCount: {
                        $size: {
                            $filter: {
                                input: '$applications',
                                as: 'app',
                                cond: { $eq: ['$$app.status', 1] }
                            }
                        }
                    }
                }
            },
            {
                $project: {
                    owner: 0,
                    applications: 0
                }
            },
            { $sort: { date: 1 } }
        ]).toArray();
        
        res.json(events);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch events' });
    }
});

// ---------- Get my events (for advanced users) ----------
app.get('/my-events', verifyToken, async (req, res) => {
    try {
        const db = await connectDB();
        const userRole = req.user.role;
        const userId = req.user.id;
        
        // Only Advanced Users can access this endpoint
        if (userRole !== 'Advanced User') {
            return res.status(403).json({ error: 'Access denied. This endpoint is for Advanced Users only.' });
        }
        
        // Get events created by this user with participant counts
        const events = await db.collection('events').aggregate([
            { $match: { createdBy: parseInt(userId) } },
            {
                $lookup: {
                    from: 'applications',
                    localField: 'id',
                    foreignField: 'eventId',
                    as: 'applications'
                }
            },
            {
                $addFields: {
                    participantCount: {
                        $size: {
                            $filter: {
                                input: '$applications',
                                as: 'app',
                                cond: { $eq: ['$$app.status', 1] }
                            }
                        }
                    }
                }
            },
            { $project: { applications: 0 } },
            { $sort: { date: 1 } }
        ]).toArray();
        
        res.json(events);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch my events' });
    }
});

// ---------- Get single event by ID ----------
app.get('/events/:id', async (req, res) => {
    try {
        const db = await connectDB();
        const { id } = req.params;
        
        const events = await db.collection('events').aggregate([
            {
                $match: { id: parseInt(id) }
            },
            {
                $lookup: {
                    from: 'users',
                    localField: 'createdBy',
                    foreignField: 'id',
                    as: 'owner'
                }
            },
            {
                $lookup: {
                    from: 'applications',
                    localField: 'id',
                    foreignField: 'eventId',
                    as: 'applications'
                }
            },
            {
                $addFields: {
                    ownerEmail: {
                        $ifNull: [
                            { $arrayElemAt: ['$owner.email', 0] },
                            null
                        ]
                    },
                    participantCount: {
                        $size: {
                            $filter: {
                                input: '$applications',
                                as: 'app',
                                cond: { $eq: ['$$app.status', 1] }
                            }
                        }
                    }
                }
            },
            {
                $project: {
                    owner: 0,
                    applications: 0
                }
            }
        ]).toArray();
        
        if (events.length === 0) {
            return res.status(404).json({ error: 'Event not found' });
        }
        
        res.json(events[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch event' });
    }
});

//----------- Get Applications (All events user has applied for) ----------
app.get('/applications', verifyToken, async (req, res) => {
    try {
        const db = await connectDB();
        const userId = req.user.id;
        const applications = await db.collection('events').aggregate([
            { 
                $lookup: { from: "applications", localField: "id", foreignField: "eventId", as: "apps" }
            },
            { 
                $match: { apps: { $elemMatch: { userId: parseInt(userId), status: { $in: [1, 2] } } } }
            },
            {
                $lookup: {
                    from: 'users',
                    localField: 'createdBy',
                    foreignField: 'id',
                    as: 'owner'
                }
            },
            {
                $lookup: {
                    from: 'applications',
                    localField: 'id',
                    foreignField: 'eventId',
                    as: 'applications'
                }
            },
            {
                $addFields: {
                    ownerEmail: {
                        $ifNull: [
                            { $arrayElemAt: ['$owner.email', 0] },
                            null
                        ]
                    },
                    participantCount: {
                        $size: {
                            $filter: {
                                input: '$applications',
                                as: 'app',
                                cond: { $eq: ['$$app.status', 1] }
                            }
                        }
                    }
                }
            },
            {
                $project: {
                    owner: 0,
                    applications: 0,
                    apps: 0
                }
            },
            { $sort: { date: 1 } }
        ]).toArray();
        res.json(applications);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch applications' });
    }
});

//----------- Get History ----------
app.get('/history', verifyToken, async (req, res) => {
    try {
        const db = await connectDB();
        const now = new Date();
        const history = await db.collection('events').aggregate([
            { 
                $lookup: { from: "applications", localField: "id", foreignField: "eventId", as: "apps" }
            },
            { 
                $match: { apps: { $elemMatch: { userEmail: req.user.email, status: 1 } },$expr: { $lt: [ { $toDate: "$date" }, now ] }}
            },
            {
                $lookup: {
                    from: 'users',
                    localField: 'createdBy',
                    foreignField: 'id',
                    as: 'owner'
                }
            },
            {
                $lookup: {
                    from: 'applications',
                    localField: 'id',
                    foreignField: 'eventId',
                    as: 'applications'
                }
            },
            {
                $addFields: {
                    ownerEmail: {
                        $ifNull: [
                            { $arrayElemAt: ['$owner.email', 0] },
                            null
                        ]
                    },
                    participantCount: {
                        $size: {
                            $filter: {
                                input: '$applications',
                                as: 'app',
                                cond: { $eq: ['$$app.status', 1] }
                            }
                        }
                    }
                }
            },
            {
                $project: {
                    owner: 0,
                    applications: 0,
                    apps: 0
                }
            }
        ]).toArray();
        res.json(history);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch history' });
    }
});

//----------- Get Past Events ----------\
app.get('/past', async (req, res) => {
    try {
        const db = await connectDB();
        const todayEnd = new Date();
        todayEnd.setHours(23, 59, 59, 999);

        const events = await db.collection('events').aggregate([
            {
                $match: {
                    $expr: {
                        $lte: [ { $toDate: "$date" }, todayEnd ]  // all events with date <= end of today
                    }
                }
            },
            {
                $lookup: {
                    from: 'users',
                    localField: 'createdBy',
                    foreignField: 'id',
                    as: 'owner'
                }
            },
            {
                $lookup: {
                    from: 'applications',
                    localField: 'id',
                    foreignField: 'eventId',
                    as: 'applications'
                }
            },
            {
                $addFields: {
                    ownerEmail: {
                        $ifNull: [
                            { $arrayElemAt: ['$owner.email', 0] },
                            null
                        ]
                    },
                    participantCount: {
                        $size: {
                            $filter: {
                                input: '$applications',
                                as: 'app',
                                cond: { $eq: ['$$app.status', 1] }
                            }
                        }
                    }
                }
            },
            {
                $project: {
                    owner: 0,
                    applications: 0
                }
            },
            { $sort: { date: -1 } }
        ]).toArray();

        res.json(events);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch past events' });
    }
});

// ---------- Get all participant of an Event ----------
app.get('/eventParticipants/:id', verifyToken, async (req, res) => {
    try {
        const db = await connectDB();
        const { id } = req.params;
        const userId = req.user.id;
        const userRole = req.user.role;

        // Check ownership for Advanced Users
        if (userRole === 'Advanced User') {
            const event = await db.collection('events').findOne({ id: parseInt(id) });
            if (!event) {
                return res.status(404).json({ error: 'Event not found' });
            }
            if (event.createdBy !== parseInt(userId)) {
                return res.status(403).json({ error: 'You do not have permission to view participants of this event.' });
            }
        }

        const participants = await db.collection('applications').aggregate([
            { $match: {eventId: parseInt(id), status: 1} },
            { $lookup: {from: 'users', localField: 'userId', foreignField: 'id', as: 'user'}},
            { $unwind: '$user' },
            { $project: {_id: 0, name: '$user.name'}}
        ]).toArray();

        res.json({ participants });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch event participants' });
    }
});

// ---------- Create new event ----------
app.post('/events', verifyToken, upload.single('image'), async (req, res) => {
    try {
        const db = await connectDB();
        const { title, date, location, permission, participationLimit, description } = req.body;

        if (!title || !date || !location || !participationLimit) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        // Get next event ID
        const counter = await db.collection('counters').findOneAndUpdate(
            { _id: 'eventId' },
            { $inc: { seq: 1 } },
            { returnDocument: 'after', upsert: true }
        );

        const eventId = counter.value?.seq || (await db.collection('counters').findOne({ _id: 'eventId' })).seq;

        const newEvent = {
            id: eventId,
            title,
            date,
            location,
            permission,
            participationLimit: parseInt(participationLimit),
            description: description || '',
            imagePath: req.file ? `uploads/${req.file.filename}` : null,
            createdBy: req.user.id,
            createdAt: new Date().toISOString()
        };

        const result = await db.collection('events').insertOne(newEvent);
        console.log('Event created with id:', eventId);
        res.json({ message: 'Event created successfully', id: eventId, ...newEvent });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to create event' });
    }
});

// ---------- Update event ----------
app.put('/events/:id', verifyToken, upload.single('image'), async (req, res) => {
    try {
        const db = await connectDB();
        const { id } = req.params;
        const { title, date, location, permission, participationLimit, description, removeImage } = req.body;
        const userId = req.user.id;
        const userRole = req.user.role;
        
        if (!title || !date || !location) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        const event = await db.collection('events').findOne({ id: parseInt(id) });
        if (!event) return res.status(404).json({ error: 'Event not found' });
        
        // Ownership check: Advanced Users can only edit their own events
        if (userRole === 'Advanced User' && event.createdBy !== parseInt(userId)) {
            return res.status(403).json({ error: 'You do not have permission to edit this event. You can only edit events you created.' });
        }
        const oldLimit = event.participationLimit;
        const oldDate = event.date;
        const newLimit = parseInt(participationLimit);

        const currentCount = await db.collection('applications').countDocuments({
            eventId: parseInt(id),
            status: 1
        });
        if (currentCount > newLimit) {
            return res.status(400).json({
                error: `Cannot reduce participation limit below current confirmed participants (${currentCount})`
            });
        }

        const updateData = {
            title,
            date,
            location,
            permission,
            participationLimit: parseInt(participationLimit),
            description: description || '',
            updatedAt: new Date().toISOString()
        };
        if (req.file) {
            updateData.imagePath = `uploads/${req.file.filename}`;
        } else if (removeImage === 'true') {
            updateData.imagePath = null;
        }
        
        const result = await db.collection('events').findOneAndUpdate(
            { id: parseInt(id) },
            { $set: updateData },
            { returnDocument: 'after' }
        );

        const slotsAdded = newLimit - oldLimit;
        if (slotsAdded > 0) {
            const waitingUsers = await db.collection('applications')
                .find({ eventId: parseInt(id), status: 2 })
                .sort({ appliedAt: 1 })  // oldest first
                .limit(slotsAdded)
                .toArray();

            if (waitingUsers.length > 0) {
                const updatePromises = waitingUsers.map(u =>
                    db.collection('applications').updateOne(
                        { _id: u._id },
                        { $set: { status: 1 } }
                    )
                );
                await Promise.all(updatePromises);
            }
        }

        // If date changed, send notifications
        if (oldDate !== date) {
            // Fetch all userIds of participants in this event with status = 1
            const participants = await db.collection('applications').find({
                eventId: parseInt(id),
                status: 1
            }).toArray();
            const participantIds = participants.map(p => p.userId);

            // Fetch emails of those participants who are Administrator or Advanced User
            const usersToNotify = await db.collection('users').find({
                id: { $in: participantIds },
                role: { $in: ['Administrator', 'Advanced User'] }
            }).toArray();

            // Send emails in parallel
            const emailPromises = usersToNotify.map(user => {
                const subject = `Event "${title}" Date Changed`;
                const body = `Hello ${user.name},\n\nThe event "${title}" has a new date: ${date} (previous date was ${oldDate}).\nPlease take note.\n\nBest regards,\nEvent System`;

                sendEmail(user.email, subject, body);
            });
            await Promise.all(emailPromises);
        }

        // Return the updated document under an `event` key instead of spreading
        res.json({ message: 'Event updated successfully', event: result.value });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to update event' });
    }
});

// ----------- Edit User -------------

// fetch
app.get('/users/:id/retrieve', verifyToken, async (req, res) => {
    try {
        const db = await connectDB();
        const { id } = req.params;

        const user = await db.collection('users').findOne(
            { _id: new ObjectId(id) },
            { projection: { password: 0 } } // optional safety
        );

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.json(user);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Failed to load user' });
    }
});

// update
app.put('/users/:id/send', verifyToken, async (req, res) => {
    try {
        const db = await connectDB();
        const { id } = req.params;
        const { name, role, occupation, isSelf } = req.body;

        const updateData = {};
        if (name) updateData.name = name;
        if (role) updateData.role = role;
        if (occupation) updateData.occupation = occupation;

        if(Object.keys(updateData).length === 0) {
            return res.status(400).json({message: "? No fields to update"});
        }

        const result = await db.collection('users').updateOne(
            { _id: new ObjectId(id) },
            { $set: updateData }
        );

        if(result.matchedCount === 0) return res.status(404).json({message: "User not found"});

        let token = null;
        if (isSelf) {
            const updatedUser = await db.collection('users').findOne({ _id: new ObjectId(id) });
            token = jwt.sign(
                { email: updatedUser.email, name: updatedUser.name, id: updatedUser.id, role: updatedUser.role, occupation: updatedUser.occupation },
                SECRET_KEY,
                { expiresIn: '1h' }
            );
        }

        res.json({success: true, message: "User updated successfully.", token});

    } catch (err) {
        console.error(err);
        res.status(500).json({message: "Failed to update user..."});
    }
});

// ---------- Delete User ------------
app.delete('/users/:id', async (req, res) => {
    try {
        const db = await connectDB();
        const mongoId = req.params.id;
        const objectId = new ObjectId(mongoId);

        const user = await db.collection('users').findOne({ _id: objectId });
        if (!user) return res.json({ success: false, message: "User not found" });

        const userId = user.id;
        const deleteResult = await db.collection('users').deleteOne({ _id: objectId });
        if (deleteResult.deletedCount === 0)
            return res.status(500).json({ success: false, message: "User deletion failed" });

        const userApps = await db.collection('applications')
            .find({ userId: userId, status: { $in: [1, 2] } })
            .toArray();
        await db.collection('applications').updateMany(
            { userId: userId },
            { $set: { status: 0 } }
        );

        for (const app of userApps) {
            if (app.status === 1) {
                const oldestWaiting = await db.collection('applications')
                    .find({ eventId: app.eventId, status: 2 }) // waiting list
                    .sort({ appliedAt: 1 })                    // oldest first
                    .limit(1)
                    .toArray();

                if (oldestWaiting.length > 0) {
                    await db.collection('applications').updateOne(
                        { _id: oldestWaiting[0]._id },
                        { $set: { status: 1 } }
                    );
                }
            }
        }

        res.json({ success: true, message: "User deleted and applications fully cancelled successfully." });

    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Failed to delete user...' });
    }
});

// ---------- Delete event ----------
app.delete('/events/:id', verifyToken, async (req, res) => {
    try {
        const db = await connectDB();
        const { id } = req.params;
        const userId = req.user.id;
        const userRole = req.user.role;
        
        const event = await db.collection('events').findOne({ id: parseInt(id) });
        if (!event) {
            return res.status(404).json({ error: 'Event not found' });
        }
        
        // Ownership check: Advanced Users can only delete their own events
        if (userRole === 'Advanced User' && event.createdBy !== parseInt(userId)) {
            return res.status(403).json({ error: 'You do not have permission to delete this event. You can only delete events you created.' });
        }
        
        const result = await db.collection('events').deleteOne({ id: parseInt(id) });

        if (result.deletedCount === 0) {
            return res.status(404).json({ error: 'Event not found' });
        }
        res.json({ message: 'Event deleted successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to delete event' });
    }
});

// Check if current user has applied for an event
app.get('/events/:id/applied', verifyToken, async (req, res) => {
    try {
        const db = await connectDB();
        const { id } = req.params;
        const userId = req.user.id;

        const application = await db.collection('applications')
            .find({
                eventId: parseInt(id),
                userId: userId
            })
            .sort({ appliedAt: -1 }) // most recent first
            .limit(1)
            .toArray();

        if (application.length === 0) {
            return res.json({ status: 0 }); // 0 = not applied
        }

        res.json({ status: application[0].status });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to check application' });
    }
});

// ---------- Apply for an event ----------
app.post('/events/:id/apply', verifyToken, async (req, res) => {
    try {
        const db = await connectDB();
        const { id } = req.params;
        const userId = req.user.id;
        let applyStatus = 1;

        // Check if event exists
        const event = await db.collection('events').findOne({ id: parseInt(id) });
        if (!event) return res.status(404).json({ error: 'Event not found' });

        //Check participation limit
        const currentCount = await db.collection('applications').countDocuments({
            eventId: parseInt(id),
            status: 1 
        });
        if (currentCount >= event.participationLimit) { applyStatus = 2; }

        // Create application record
        const application = {
            eventId: parseInt(id),
            userId: userId,
            appliedAt: new Date().toISOString(),
            status: applyStatus
        };

        await db.collection('applications').insertOne(application);
        console.log(`User ${userId} applied for event ${id}`);

        if (applyStatus === 2) {
            return res.json({ message: 'Participation limit reached. You have been placed on the waiting list.' });
        }
        res.json({ message: 'Application submitted successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to apply for event' });
    }
});

// ---------- Retract application ----------
app.patch('/events/:id/apply', verifyToken, async (req, res) => {
    try {
        const db = await connectDB();
        const { id } = req.params;
        const userId = req.user.id;

        const currentApp = await db.collection('applications').findOne({
            eventId: parseInt(id),
            userId: userId,
            status: { $in: [1, 2] } // only status 1 or 2
        });

        if (!currentApp) {
            return res.status(404).json({ error: 'Application not found or already retracted' });
        }

        const previousStatus = currentApp.status; 
        await db.collection('applications').updateOne(
            { _id: currentApp._id },
            { $set: { status: 0 } }
        );

        if (previousStatus === 1) {
            const oldestWaiting = await db.collection('applications')
                .find({ eventId: parseInt(id), status: 2 })
                .sort({ appliedAt: 1 }) // oldest first
                .limit(1)
                .toArray();

            if (oldestWaiting.length > 0) {
                await db.collection('applications').updateOne(
                    { _id: oldestWaiting[0]._id },
                    { $set: { status: 1 } }
                );
            }
        }

        res.json({ message: 'Application retracted successfully' });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to retract application' });
    }
});

// Connect to DB
connectDB();

// Export the app for Vercel
module.exports = app;