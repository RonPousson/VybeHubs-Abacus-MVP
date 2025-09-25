const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const Redis = require('redis');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: { origin: process.env.FRONTEND_URL || "*", methods: ["GET", "POST"] }
});

// Middleware
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));
app.use(express.static('.'));

// Database (Postgres)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://localhost:5432/vybehubs',
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Redis
let redisClient;
try {
  redisClient = Redis.createClient(process.env.REDIS_URL || 'redis://localhost:6379');
  redisClient.connect();
} catch (err) {
  console.log('⚠️ Redis not available, using in-memory storage');
  redisClient = null;
}

// File Upload
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = 'uploads/';
    if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => cb(null, uuidv4() + path.extname(file.originalname))
});

const upload = multer({ 
  storage, 
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|mp3|wav|ogg|webm/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    if (mimetype && extname) return cb(null, true);
    cb(new Error('Invalid file type'));
  }
});

// Demo In-Memory Stores
let users = new Map();
let communities = new Map();
let messages = new Map();
let userStreaks = new Map();
let challenges = new Map();
let checkIns = new Map();

// Initialize Demo Data
function initializeDemoData() {
  const demoCommunities = [
    {
      id: 'crypto-degens',
      name: 'Crypto Degens',
      description: 'High-risk, high-reward crypto trading strategies',
      category: 'Finance',
      memberCount: 1247,
      isPrivate: false,
      tags: ['crypto', 'trading', 'defi'],
      location: { lat: 40.7128, lng: -74.0060, name: 'New York, NY' },
      reputation: 4.2,
      challenges: ['Daily Trading Challenge', 'Portfolio Growth Contest']
    },
    {
      id: 'urban-gardeners',
      name: 'Urban Gardeners',
      description: 'Growing food in small city spaces',
      category: 'Lifestyle',
      memberCount: 892,
      isPrivate: false,
      tags: ['gardening', 'sustainability', 'urban'],
      location: { lat: 37.7749, lng: -122.4194, name: 'San Francisco, CA' },
      reputation: 4.7,
      challenges: ['30-Day Growth Challenge', 'Seed Swap Challenge']
    },
    {
      id: 'midnight-coders',
      name: 'Midnight Coders',
      description: 'Late-night programming sessions and code reviews',
      category: 'Technology',
      memberCount: 2156,
      isPrivate: true,
      tags: ['programming', 'coding', 'tech'],
      location: { lat: 47.6062, lng: -122.3321, name: 'Seattle, WA' },
      reputation: 4.5,
      challenges: ['Code-a-thon Weekend', 'Bug Bounty Hunt']
    },
    {
      id: 'vinyl-collectors',
      name: 'Vinyl Collectors',
      description: 'Rare records, trading, and music discovery',
      category: 'Music',
      memberCount: 634,
      isPrivate: false,
      tags: ['vinyl', 'music', 'collecting'],
      location: { lat: 34.0522, lng: -118.2437, name: 'Los Angeles, CA' },
      reputation: 4.3,
      challenges: ['Monthly Discovery Challenge', 'Rare Find Contest']
    },
    {
      id: 'drone-pilots',
      name: 'Drone Pilots',
      description: 'Aerial photography and drone racing enthusiasts',
      category: 'Technology',
      memberCount: 1089,
      isPrivate: false,
      tags: ['drones', 'photography', 'racing'],
      location: { lat: 39.7392, lng: -104.9903, name: 'Denver, CO' },
      reputation: 4.1,
      challenges: ['Aerial Photo Contest', 'Racing League']
    },
    {
      id: 'sourdough-masters',
      name: 'Sourdough Masters',
      description: 'Perfecting the art of sourdough bread making',
      category: 'Food',
      memberCount: 756,
      isPrivate: false,
      tags: ['baking', 'sourdough', 'food'],
      location: { lat: 45.5152, lng: -122.6784, name: 'Portland, OR' },
      reputation: 4.8,
      challenges: ['Perfect Loaf Challenge', 'Starter Sharing']
    }
  ];

  demoCommunities.forEach(community => {
    communities.set(community.id, community);
    messages.set(community.id, []);
    challenges.set(community.id, community.challenges || []);
  });

  console.log('✅ Demo data initialized');
}

// JWT Auth Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET || 'vybehubs-secret', (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Helper Functions
function calculateDistance(lat1, lon1, lat2, lon2) {
  const R = 6371; // Earth's radius in km
  const dLat = deg2rad(lat2 - lat1);
  const dLon = deg2rad(lon2 - lon1);
  const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
    Math.cos(deg2rad(lat1)) * Math.cos(deg2rad(lat2)) * 
    Math.sin(dLon/2) * Math.sin(dLon/2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
  return R * c;
}

function deg2rad(deg) {
  return deg * (Math.PI/180);
}

// --- API Routes ---

// Health Routes
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Authentication Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    if (users.has(email)) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = uuidv4();
    
    const user = {
      id: userId,
      username,
      email,
      password: hashedPassword,
      createdAt: new Date(),
      streak: 0,
      reputation: 100,
      badges: [],
      location: null
    };

    users.set(email, user);
    userStreaks.set(userId, { current: 0, lastActive: null, best: 0 });

    const token = jwt.sign(
      { userId, email, username },
      process.env.JWT_SECRET || 'vybehubs-secret',
      { expiresIn: '24h' }
    );

    res.json({ token, user: { id: userId, username, email, streak: 0, reputation: 100 } });
  } catch (error) {
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = users.get(email);

    if (!user || !await bcrypt.compare(password, user.password)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Update streak
    const streak = userStreaks.get(user.id) || { current: 0, lastActive: null, best: 0 };
    const now = new Date();
    const lastActive = streak.lastActive ? new Date(streak.lastActive) : null;
    
    if (lastActive) {
      const daysDiff = Math.floor((now - lastActive) / (1000 * 60 * 60 * 24));
      if (daysDiff === 1) {
        streak.current += 1;
        streak.best = Math.max(streak.best, streak.current);
      } else if (daysDiff > 1) {
        streak.current = 1;
      }
    } else {
      streak.current = 1;
    }
    
    streak.lastActive = now;
    userStreaks.set(user.id, streak);

    const token = jwt.sign(
      { userId: user.id, email, username: user.username },
      process.env.JWT_SECRET || 'vybehubs-secret',
      { expiresIn: '24h' }
    );

    res.json({ 
      token, 
      user: { 
        id: user.id, 
        username: user.username, 
        email, 
        streak: streak.current,
        reputation: user.reputation || 100
      } 
    });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// Communities Routes
app.get('/api/communities', (req, res) => {
  const { category, search, lat, lng, radius = 50 } = req.query;
  let communityList = Array.from(communities.values());

  // Filter by category
  if (category && category !== 'all') {
    communityList = communityList.filter(c => 
      c.category.toLowerCase() === category.toLowerCase()
    );
  }

  // Search filter
  if (search) {
    const searchLower = search.toLowerCase();
    communityList = communityList.filter(c =>
      c.name.toLowerCase().includes(searchLower) ||
      c.description.toLowerCase().includes(searchLower) ||
      c.tags.some(tag => tag.toLowerCase().includes(searchLower))
    );
  }

  // Location filter
  if (lat && lng) {
    const userLat = parseFloat(lat);
    const userLng = parseFloat(lng);
    const radiusKm = parseFloat(radius);

    communityList = communityList.filter(c => {
      if (!c.location) return false;
      
      const distance = calculateDistance(
        userLat, userLng,
        c.location.lat, c.location.lng
      );
      
      return distance <= radiusKm;
    }).map(c => ({
      ...c,
      distance: calculateDistance(userLat, userLng, c.location.lat, c.location.lng)
    })).sort((a, b) => a.distance - b.distance);
  }

  res.json(communityList);
});

app.get('/api/communities/:id', (req, res) => {
  const community = communities.get(req.params.id);
  if (!community) {
    return res.status(404).json({ error: 'Community not found' });
  }
  res.json(community);
});

app.get('/api/communities/:id/messages', authenticateToken, (req, res) => {
  const communityMessages = messages.get(req.params.id) || [];
  res.json(communityMessages);
});

app.get('/api/communities/:id/challenges', (req, res) => {
  const communityChallenges = challenges.get(req.params.id) || [];
  res.json(communityChallenges);
});

// Check-in Routes
app.post('/api/checkin', authenticateToken, (req, res) => {
  const { communityId, lat, lng, message } = req.body;
  const userId = req.user.userId;
  
  const checkIn = {
    id: uuidv4(),
    userId,
    communityId,
    location: { lat, lng },
    message,
    timestamp: new Date()
  };

  if (!checkIns.has(communityId)) {
    checkIns.set(communityId, []);
  }
  
  checkIns.get(communityId).push(checkIn);
  
  // Update user reputation
  const user = Array.from(users.values()).find(u => u.id === userId);
  if (user) {
    user.reputation = (user.reputation || 100) + 5;
  }

  res.json({ success: true, checkIn });
});

app.get('/api/communities/:id/checkins', (req, res) => {
  const communityCheckIns = checkIns.get(req.params.id) || [];
  res.json(communityCheckIns);
});

// User Routes
app.get('/api/user/streak', authenticateToken, (req, res) => {
  const streak = userStreaks.get(req.user.userId) || { current: 0, best: 0 };
  res.json(streak);
});

// File Upload Routes
app.post('/api/upload/voice', authenticateToken, upload.single('voice'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }
  
  res.json({ 
    success: true, 
    filename: req.file.filename,
    url: `/uploads/${req.file.filename}`
  });
});

app.use('/uploads', express.static('uploads'));

// Frontend Route
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Socket.IO for Real-time Features
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('join-community', (communityId) => {
    socket.join(communityId);
    console.log(`User ${socket.id} joined community ${communityId}`);
  });

  socket.on('send-message', (data) => {
    const { communityId, message, userId, username, type = 'text', voiceUrl, disappearing = false } = data;
    
    const messageObj = {
      id: uuidv4(),
      userId,
      username,
      message,
      type,
      voiceUrl,
      disappearing,
      timestamp: new Date(),
      expiresAt: disappearing ? new Date(Date.now() + 24 * 60 * 60 * 1000) : null
    };

    if (!messages.has(communityId)) {
      messages.set(communityId, []);
    }
    
    messages.get(communityId).push(messageObj);
    
    // Broadcast to community
    io.to(communityId).emit('new-message', messageObj);
    
    // Clean up expired messages
    if (disappearing) {
      setTimeout(() => {
        const communityMessages = messages.get(communityId) || [];
        const filteredMessages = communityMessages.filter(m => m.id !== messageObj.id);
        messages.set(communityId, filteredMessages);
        io.to(communityId).emit('message-expired', messageObj.id);
      }, 24 * 60 * 60 * 1000);
    }
  });

  socket.on('typing', (data) => {
    socket.to(data.communityId).emit('user-typing', {
      userId: data.userId,
      username: data.username
    });
  });

  socket.on('stop-typing', (data) => {
    socket.to(data.communityId).emit('user-stop-typing', {
      userId: data.userId
    });
  });

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
  });
});

// Initialize demo data
initializeDemoData();

// Export app for Vercel serverless deployment
module.exports = app;
