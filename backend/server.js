/**
 * server.js — GuardianBox Backend (The Blind Server)
 * ────────────────────────────────────────────────────
 * This server is "zero-knowledge." It stores and retrieves encrypted blobs
 * but has NO ability to decrypt them. It never sees passwords or keys.
 *
 * Stack: Node.js 20+, Express 4, better-sqlite3, node-cron, MinIO/S3
 */

import express        from 'express';
import cors           from 'cors';
import helmet         from 'helmet';
import morgan         from 'morgan';
import rateLimit      from 'express-rate-limit';
import { db }         from './db.js';
import { startCron }  from './cron.js';
import fileRoutes     from './routes/files.js';

const app  = express();
const PORT = process.env.PORT || 4000;

// ─── Security Middleware ───────────────────────────────────────────────────────

/**
 * Helmet adds HTTP security headers:
 *  - X-Frame-Options: DENY       → prevents clickjacking
 *  - X-Content-Type-Options      → prevents MIME sniffing
 *  - Strict-Transport-Security   → forces HTTPS
 *  - Content-Security-Policy     → restricts script sources
 *  - Permissions-Policy          → restricts browser APIs
 */
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc:  ["'self'"],
        objectSrc:  ["'none'"],
        upgradeInsecureRequests: [],
      },
    },
  })
);

/**
 * CORS — only allow the frontend origin.
 * We NEVER allow credentials; there is nothing to authenticate against.
 */
app.use(
  cors({
    origin: [
  'http://localhost:5173',
  'http://16.112.68.38:8080',
  'https://guardian-box-abc.vercel.app'
],
     methods:     ['GET', 'POST', 'DELETE'],
    credentials: false,
  })
);

/**
 * Rate Limiting — prevent abuse of the upload/download endpoints.
 * 60 requests per 15-minute window per IP.
 */
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max:      60,
  message:  { error: 'Too many requests, please try again later.' },
});
app.use(limiter);

app.use(morgan('combined'));             // HTTP access logging
app.use(express.json({ limit: '1mb' })); // metadata only; blobs go via multipart

// ─── Routes ───────────────────────────────────────────────────────────────────

app.use('/api/files', fileRoutes);

/**
 * Health check — useful for load balancer / uptime monitors.
 * Returns server status without leaking any internal state.
 */
app.get('/health', (req, res) => {
  res.json({ status: 'ok', zero_knowledge: true });
});

// ─── 404 Handler ──────────────────────────────────────────────────────────────

app.use((req, res) => {
  res.status(404).json({ error: 'Not found.' });
});

// ─── Global Error Handler ─────────────────────────────────────────────────────

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('[ERROR]', err.message);
  // Never leak stack traces to clients
  res.status(err.status || 500).json({
    error: err.message || 'Internal server error.',
  });
});

// ─── Startup ──────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`
  ╔═══════════════════════════════════════════╗
  ║     GuardianBox — Zero-Knowledge Server   ║
  ║     Port: ${PORT}                             ║
  ║     This server is cryptographically BLIND║
  ╚═══════════════════════════════════════════╝
  `);
  startCron();  // Begin hourly cleanup of expired files
});

export default app;
