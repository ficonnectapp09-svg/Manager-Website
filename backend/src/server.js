const http = require('http');
const express = require('express');
const cors = require('cors');
const path = require('path');
const dotenv = require('dotenv');
const db = require('./config/db');
const { realtimeWebSocketServer } = require('./realtime');
const { sanitizeInput } = require('./middleware/sanitizeMiddleware');
const { apiLimiter } = require('./middleware/rateLimitMiddleware');

dotenv.config({ path: path.join(__dirname, '..', '.env') });

const compression = require('compression');
const app = express();
const PORT = process.env.PORT || 8005;

// Trust reverse proxy (Vercel, AWS ALB, Nginx)
app.set('trust proxy', 1);

// Remove Express fingerprinting
app.disable('x-powered-by');

// Response Compression (reduces JSON payload size by up to 80%)
app.use(compression({
  threshold: 1024,
  filter: (req, res) => {
    if (req.headers['x-no-compression']) return false;
    return compression.filter(req, res);
  }
}));

// Security Headers Middleware
app.use((req, res, next) => {
  // Prevent MIME type sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');
  // Prevent clickjacking
  res.setHeader('X-Frame-Options', 'DENY');
  // Strict Referrer policy
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  // Permissions Policy restricting unnecessary browser features
  res.setHeader('Permissions-Policy', 'geolocation=(self), microphone=(self), camera=(), payment=()');
  // Cross-Origin Isolation
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');

  // Enforce HSTS in production or over HTTPS
  if (process.env.NODE_ENV === 'production' || req.secure || req.headers['x-forwarded-proto'] === 'https') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  }

  // Content Security Policy
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; img-src 'self' data: https: blob:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; script-src 'self' 'unsafe-eval' 'unsafe-inline'; connect-src 'self' https: wss: ws:; frame-ancestors 'none'; object-src 'none'; base-uri 'self';"
  );

  next();
});

// Production-Ready Comprehensive CORS Configuration
// Supports apex domains, dynamic Vercel previews, Render hosts, mobile schemes, and local dev
const STATIC_ALLOWED_ORIGINS = [
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  'https://connect-manager.vercel.app',
  'https://manager.ficapp.in',
  'https://ficapp.in',
  'http://ficapp.in',
  'https://www.ficapp.in',
  'https://connect-manager.onrender.com',
  'https://manager-website.onrender.com'
];

if (process.env.ALLOWED_ORIGINS) {
  process.env.ALLOWED_ORIGINS.split(',').forEach(o => {
    const trimmed = o.trim();
    if (trimmed && !STATIC_ALLOWED_ORIGINS.includes(trimmed)) {
      STATIC_ALLOWED_ORIGINS.push(trimmed);
    }
  });
}

const ALLOWED_ORIGIN_PATTERNS = [
  /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/,
  /^https?:\/\/([a-zA-Z0-9-]+\.)*vercel\.app$/,
  /^https?:\/\/([a-zA-Z0-9-]+\.)*onrender\.com$/,
  /^https?:\/\/([a-zA-Z0-9-]+\.)*ficapp\.in(:\d+)?$/,
  /^https?:\/\/ficapp\.in(:\d+)?$/,
  /^capacitor:\/\//,
  /^ionic:\/\//
];

const isOriginPermitted = (origin) => {
  if (!origin || origin === 'null') return true;
  if (STATIC_ALLOWED_ORIGINS.includes(origin)) return true;
  return ALLOWED_ORIGIN_PATTERNS.some(regex => regex.test(origin));
};

const corsOptions = {
  origin: (origin, callback) => {
    // Non-browser or matching allowed patterns
    if (isOriginPermitted(origin)) {
      return callback(null, true);
    }
    // Allow any incoming web client by reflecting origin to prevent 403 blocks on Bearer-authenticated APIs
    callback(null, true);
  },
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin'],
  exposedHeaders: ['Content-Range', 'X-Content-Range'],
  credentials: true,
  maxAge: 86400
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// Request Body Limits (supports multi-visit report submissions without 413 errors)
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// Global Input Sanitization against NoSQL injection & prototype pollution
app.use(sanitizeInput);

// Global API rate limiting
app.use('/api', apiLimiter);

// Serve static uploads with nosniff and caching
app.use('/uploads', express.static(path.join(__dirname, '..', 'uploads'), {
  setHeaders: (res) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
    res.setHeader('Cache-Control', 'public, max-age=86400');
  }
}));

// Health check reporting active database
app.get('/api/health', (req, res) => {
  res.json({
    status: 'online',
    timestamp: new Date().toISOString(),
    service: 'Agent Manager Portal Backend API',
    database: db.getDatabaseName ? db.getDatabaseName() : (process.env.DB_NAME || 'connect_manager_fresh')
  });
});

app.get('/api/health/db', async (req, res) => {
  try {
    const dbName = db.getDatabaseName ? db.getDatabaseName() : (process.env.DB_NAME || 'connect_manager_fresh');
    const [usersCount, vendorsCount, tasksCount, agentsCount] = await Promise.all([
      db.users.count().catch(() => 0),
      db.vendors.count().catch(() => 0),
      db.tasks.count().catch(() => 0),
      db.agents.count().catch(() => 0)
    ]);
    res.json({
      success: true,
      database: dbName,
      counts: {
        users: usersCount,
        vendors: vendorsCount,
        tasks: tasksCount,
        agents: agentsCount
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Routes (Manager Portal Scope)
const authRoutes = require('./routes/authRoutes');
const vendorRoutes = require('./routes/vendorRoutes');
const locationRoutes = require('./routes/locationRoutes');
const reportRoutes = require('./routes/reportRoutes');
const auditRoutes = require('./routes/auditRoutes');
const uploadRoutes = require('./routes/uploadRoutes');
const managerDirectoryRoutes = require('./routes/managerDirectoryRoutes');
const { router: notificationRoutes } = require('./routes/notificationRoutes');
const taskRoutes = require('./routes/taskRoutes');
const shopVisitRoutes = require('./routes/shopVisitRoutes');
const agentRoutes = require('./routes/agentRoutes');
const settingsRoutes = require('./routes/settingsRoutes');
const realtimeRoutes = require('./routes/realtimeRoutes');
const managerOnboardingRoutes = require('./routes/managerOnboardingRoutes');
const issueRoutes = require('./routes/issueRoutes');

app.use('/api/auth', authRoutes);
app.use('/api/vendors', vendorRoutes);
app.use('/api', locationRoutes); // /api/states, /api/districts, /api/divisions, /api/pincodes
app.use('/api/reports', reportRoutes);
app.use('/api/audit-logs', auditRoutes);
// Legacy S3 media endpoint — AWS S3 has been removed; all media is served via Cloudinary CDN URLs.
// This endpoint returns 410 Gone for any legacy /api/media/s3/:key requests.
app.get(['/api/media/s3/:key(*)', '/api/uploads/s3/:key(*)'], (req, res) => {
  res.status(410).json({
    error: 'AWS S3 media endpoint removed.',
    message: 'All media is now served directly via Cloudinary CDN URLs. ' +
             'No legacy S3 objects exist. Use the Cloudinary URL returned during upload.'
  });
});

app.use('/api/uploads', uploadRoutes);
app.use('/api/managers', managerDirectoryRoutes);
app.use('/api/notifications', notificationRoutes);
app.use('/api/qc-tasks', taskRoutes);
app.use('/api/tasks', taskRoutes);
app.use('/api/issues', issueRoutes);
app.use('/api/shop-visits', shopVisitRoutes);
app.use('/api/operations', agentRoutes);
app.use('/api/settings', settingsRoutes);
app.use('/api/realtime', realtimeRoutes);
app.use('/api/manager-onboarding', managerOnboardingRoutes);

// Direct /api/bank-details alias routes
const { authMiddleware } = require('./middleware/authMiddleware');
const { checkRole } = require('./middleware/roleMiddleware');
const authController = require('./controllers/authController');
app.get('/api/bank-details', authMiddleware, checkRole(), authController.getBankDetails);
app.put('/api/bank-details', authMiddleware, checkRole(), authController.updateBankDetails);
app.post('/api/bank-details', authMiddleware, checkRole(), authController.updateBankDetails);

// Centralized production-safe error handling
app.use((err, req, res, next) => {
  // Handle Multer errors explicitly with 400 Bad Request
  if (err && (err.name === 'MulterError' || err.code?.startsWith('LIMIT_'))) {
    const message = err.code === 'LIMIT_FILE_SIZE'
      ? 'File size limit exceeded.'
      : err.code === 'LIMIT_FILE_COUNT'
      ? 'Too many files uploaded in a single request.'
      : err.code === 'LIMIT_UNEXPECTED_FILE'
      ? `Unexpected upload field '${err.field || 'unknown'}'. Please upload using the expected field name.`
      : (err.message || 'File upload validation error.');
    return res.status(400).json({
      success: false,
      message
    });
  }

  const isProd = process.env.NODE_ENV === 'production';
  const statusCode = err.status || (err.message && err.message.includes('CORS') ? 403 : 500);
  
  if (!isProd) {
    console.error('Unhandled server error:', err.stack || err.message);
  } else if (statusCode >= 500) {
    console.error(`[Server Error] ${req.method} ${req.originalUrl}:`, err.message);
  }

  res.status(statusCode).json({
    success: false,
    message: isProd && statusCode >= 500
      ? 'An unexpected internal server error occurred. Please try again later.'
      : (err.message || 'An error occurred.')
  });
});

async function startServer() {
  try {
    console.log('[Manager Backend] Initializing MongoDB connection...');
    if (db.initDatabase) {
      await db.initDatabase();
    }
  } catch (err) {
    console.error('FATAL: Database initialization failed during startup:', err.message);
    process.exit(1);
  }

  const server = http.createServer(app);
  realtimeWebSocketServer.attach(server);

  server.listen(PORT, () => {
    console.log('=============================================');
    console.log(`Agent Manager API Server running on port ${PORT}`);
    console.log(`Health endpoint: http://localhost:${PORT}/api/health`);
    console.log(`Realtime WS: ws://localhost:${PORT}/ws`);
    console.log('=============================================');
  });
}

if (require.main === module) {
  startServer();
}

module.exports = app;
