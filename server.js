/**
 * SafarSaathi Production-Grade Enterprise Server & Security Architecture
 * ----------------------------------------------------------------------
 * Security Guarantees:
 *  1. ZERO hardcoded secrets, salts, or passwords in source code.
 *  2. Master admin credentials derived via Scrypt with dynamic salt.
 *  3. Cryptographically signed HMAC-SHA256 session tokens (constant-time verification).
 *  4. Single authoritative server-side data store (data/production_db.json).
 *  5. Server-side transactional anti-duplicate UTR validation.
 *  6. Sanitized public radar endpoints (zero driver PII/bank data leaked).
 *  7. Zero external runtime dependencies (native Node.js core modules only).
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const crypto = require('crypto');

const PORT = process.env.PORT || 5000;
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'production_db.json');
const SECRET_FILE = path.join(DATA_DIR, '.admin_secret.json');

// --- SECURE CRYPTOGRAPHIC CREDENTIALS & TOKENS ---
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const TOKEN_EXPIRY_MS = 8 * 60 * 60 * 1000; // 8 hours session expiry

let ADMIN_SALT = process.env.ADMIN_SALT || null;
let ADMIN_SCRYPT_HASH = process.env.ADMIN_SCRYPT_HASH || null;

/**
 * Initialize or load master admin credentials.
 * ZERO hardcoded secrets: must come from environment variable or securely generated on first boot.
 */
function initAdminCredentials() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }

  // 1. If explicit password provided via environment variable
  if (process.env.ADMIN_PASSWORD) {
    ADMIN_SALT = crypto.randomBytes(16).toString('hex');
    ADMIN_SCRYPT_HASH = crypto.scryptSync(process.env.ADMIN_PASSWORD, ADMIN_SALT, 64).toString('hex');
    console.log('[SECURITY] Master admin credentials initialized from ADMIN_PASSWORD environment variable.');
    return;
  }

  // 2. If pre-computed salt and scrypt hash provided via environment variables
  if (process.env.ADMIN_SALT && process.env.ADMIN_SCRYPT_HASH) {
    ADMIN_SALT = process.env.ADMIN_SALT;
    ADMIN_SCRYPT_HASH = process.env.ADMIN_SCRYPT_HASH;
    console.log('[SECURITY] Master admin credentials loaded from ADMIN_SALT/ADMIN_SCRYPT_HASH environment variables.');
    return;
  }

  // 3. If saved in local protected secret file
  if (fs.existsSync(SECRET_FILE)) {
    try {
      const saved = JSON.parse(fs.readFileSync(SECRET_FILE, 'utf8'));
      if (saved.salt && saved.hash) {
        ADMIN_SALT = saved.salt;
        ADMIN_SCRYPT_HASH = saved.hash;
        console.log('[SECURITY] Master admin credentials loaded from persistent secret store.');
        return;
      }
    } catch (e) {}
  }

  // 4. Generate a secure random master password on first boot
  const generatedPassword = crypto.randomBytes(12).toString('base64url');
  ADMIN_SALT = crypto.randomBytes(16).toString('hex');
  ADMIN_SCRYPT_HASH = crypto.scryptSync(generatedPassword, ADMIN_SALT, 64).toString('hex');

  try {
    fs.writeFileSync(SECRET_FILE, JSON.stringify({ salt: ADMIN_SALT, hash: ADMIN_SCRYPT_HASH }, null, 2), { mode: 0o600 });
  } catch (e) {}

  console.log('===================================================================================');
  console.log('[SECURITY NOTICE] No ADMIN_PASSWORD environment variable was supplied.');
  console.log(`Generated secure master admin password: ${generatedPassword}`);
  console.log(`Stored scrypt hash in: ${SECRET_FILE}`);
  console.log('You can set your own permanent password anytime using:');
  console.log('  export ADMIN_PASSWORD="YourSecurePassword" && npm start');
  console.log('===================================================================================');
}

/**
 * Verify candidate password in constant time
 */
function verifyAdminSecret(candidatePassword) {
  if (!candidatePassword || typeof candidatePassword !== 'string' || !ADMIN_SALT || !ADMIN_SCRYPT_HASH) {
    return false;
  }
  try {
    const candidateHash = crypto.scryptSync(candidatePassword, ADMIN_SALT, 64).toString('hex');
    const a = Buffer.from(candidateHash, 'utf8');
    const b = Buffer.from(ADMIN_SCRYPT_HASH, 'utf8');
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch (err) {
    return false;
  }
}

/**
 * Issue a cryptographically signed HMAC-SHA256 session token
 */
function createSessionToken(username = 'admin') {
  const expiresAt = Date.now() + TOKEN_EXPIRY_MS;
  const payload = JSON.stringify({ user: username, exp: expiresAt, nonce: crypto.randomBytes(8).toString('hex') });
  const payloadB64 = Buffer.from(payload).toString('base64url');
  const signature = crypto.createHmac('sha256', SESSION_SECRET).update(payloadB64).digest('base64url');
  return { token: `${payloadB64}.${signature}`, expiresAt };
}

/**
 * Validate session token signature and expiration in constant time
 */
function verifySessionToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [payloadB64, signature] = parts;
  try {
    const expectedSig = crypto.createHmac('sha256', SESSION_SECRET).update(payloadB64).digest('base64url');
    const sigA = Buffer.from(signature, 'utf8');
    const sigB = Buffer.from(expectedSig, 'utf8');
    if (sigA.length !== sigB.length || !crypto.timingSafeEqual(sigA, sigB)) {
      return null;
    }
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
    if (Date.now() > payload.exp) {
      return null; // Expired
    }
    return payload;
  } catch (e) {
    return null;
  }
}

// --- AUTHORITATIVE SERVER-SIDE DATABASE ---
function ensureDbExists() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
  if (!fs.existsSync(DB_FILE)) {
    const initialData = {
      pendingPosts: [],
      activeDrivers: [],
      usedUtrs: [],
      registeredUsers: []
    };
    fs.writeFileSync(DB_FILE, JSON.stringify(initialData, null, 2), 'utf8');
  }
}

function readDb() {
  ensureDbExists();
  try {
    const raw = fs.readFileSync(DB_FILE, 'utf8');
    return JSON.parse(raw);
  } catch (err) {
    return { pendingPosts: [], activeDrivers: [], usedUtrs: [], registeredUsers: [] };
  }
}

function writeDb(data) {
  ensureDbExists();
  const tmpFile = DB_FILE + '.tmp.' + Date.now();
  fs.writeFileSync(tmpFile, JSON.stringify(data, null, 2), 'utf8');
  fs.renameSync(tmpFile, DB_FILE);
}

// --- HTTP REQUEST HELPERS ---
function parseJsonBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 1024 * 1024) { // 1MB limit
        req.destroy();
        reject(new Error('Payload Too Large'));
      }
    });
    req.on('end', () => {
      if (!body) return resolve({});
      try {
        resolve(JSON.parse(body));
      } catch (err) {
        reject(new Error('Invalid JSON'));
      }
    });
    req.on('error', reject);
  });
}

function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Cache-Control': 'no-store'
  });
  res.end(JSON.stringify(data));
}

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml'
};

// --- CORE SERVER ROUTER ---
const server = http.createServer(async (req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;

  // Handle CORS Pre-flight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
    });
    return res.end();
  }

  // Helper: Extract & verify Bearer token
  function authenticateAdmin(req) {
    const authHeader = req.headers['authorization'] || '';
    if (!authHeader.startsWith('Bearer ')) return null;
    const token = authHeader.substring(7).trim();
    return verifySessionToken(token);
  }

  // --- REST API ENDPOINTS ---

  // 1. Admin Login (POST /api/admin/login)
  // Evaluates strictly against scrypt-hashed secret. Zero hardcoded bypasses.
  if (pathname === '/api/admin/login' && req.method === 'POST') {
    try {
      const body = await parseJsonBody(req);
      const { passcode } = body;
      const isValid = verifyAdminSecret(passcode);
      if (!isValid) {
        return sendJson(res, 401, { error: 'Invalid admin credentials' });
      }
      const session = createSessionToken('master_admin');
      return sendJson(res, 200, {
        success: true,
        token: session.token,
        expiresAt: session.expiresAt
      });
    } catch (e) {
      return sendJson(res, 400, { error: e.message });
    }
  }

  // 2. Admin Dashboard Data (GET /api/admin/dashboard)
  if (pathname === '/api/admin/dashboard' && req.method === 'GET') {
    const adminSession = authenticateAdmin(req);
    if (!adminSession) {
      return sendJson(res, 401, { error: 'Unauthorized: Valid admin bearer token required' });
    }
    const db = readDb();
    return sendJson(res, 200, {
      success: true,
      pendingPosts: db.pendingPosts || [],
      activeDrivers: db.activeDrivers || [],
      totalUsers: (db.registeredUsers || []).length,
      feeCollected: ((db.activeDrivers || []).length) * 100
    });
  }

  // 3. Admin Approve Driver (POST /api/admin/approve)
  if (pathname === '/api/admin/approve' && req.method === 'POST') {
    const adminSession = authenticateAdmin(req);
    if (!adminSession) {
      return sendJson(res, 401, { error: 'Unauthorized: Valid admin bearer token required' });
    }
    try {
      const body = await parseJsonBody(req);
      const { postId } = body;
      const db = readDb();
      const postIndex = (db.pendingPosts || []).findIndex(p => p.id === postId);
      if (postIndex === -1) {
        return sendJson(res, 404, { error: 'Post not found in pending queue' });
      }

      const post = db.pendingPosts[postIndex];

      // Server-side strict anti-duplicate UTR validation
      if ((db.usedUtrs || []).includes(post.utr)) {
        return sendJson(res, 409, { error: `Fraud Protection: UTR ${post.utr} has already been utilized!` });
      }

      // Atomic transition: Remove from pending, add to usedUtrs, activate driver
      db.pendingPosts.splice(postIndex, 1);
      db.usedUtrs.push(post.utr);

      const newDriver = {
        id: 'driver_' + Date.now(),
        name: post.driverName,
        phone: post.driverId,
        vehicleNo: post.vehicleNo,
        photo: post.photo,
        stand: post.stand,
        lat: post.lat || 26.3465,
        lng: post.lng || 92.6815,
        fare: 15,
        battery: '98%',
        rating: 5.0,
        totalTrips: 1,
        licenseExpiry: new Date(Date.now() + 12 * 3600 * 1000).toLocaleString('en-GB'),
        expiresAt: Date.now() + 12 * 3600 * 1000,
        dutyStatus: 'on_duty',
        status: 'active'
      };

      db.activeDrivers.unshift(newDriver);
      writeDb(db);

      return sendJson(res, 200, {
        success: true,
        message: 'Driver approved and activated on live radar',
        driver: newDriver
      });
    } catch (e) {
      return sendJson(res, 400, { error: e.message });
    }
  }

  // 4. Admin Reject Driver (POST /api/admin/reject)
  if (pathname === '/api/admin/reject' && req.method === 'POST') {
    const adminSession = authenticateAdmin(req);
    if (!adminSession) {
      return sendJson(res, 401, { error: 'Unauthorized: Valid admin bearer token required' });
    }
    try {
      const body = await parseJsonBody(req);
      const { postId } = body;
      const db = readDb();
      db.pendingPosts = (db.pendingPosts || []).filter(p => p.id !== postId);
      writeDb(db);
      return sendJson(res, 200, { success: true, message: 'Post rejected' });
    } catch (e) {
      return sendJson(res, 400, { error: e.message });
    }
  }

  // 5. Driver Submit ₹100 Post (POST /api/driver/submit)
  if (pathname === '/api/driver/submit' && req.method === 'POST') {
    try {
      const body = await parseJsonBody(req);
      const { utr, vehicleNo, driverName, driverId, photo, stand, lat, lng, type } = body;

      // Strict server-side validation
      if (!utr || typeof utr !== 'string' || utr.trim().length < 12) {
        return sendJson(res, 422, { error: 'Invalid UTR: 12-digit transaction reference number is required' });
      }

      const cleanUtr = utr.trim();
      const db = readDb();

      // Check if UTR is already utilized on server
      if ((db.usedUtrs || []).includes(cleanUtr)) {
        return sendJson(res, 409, { error: 'Duplicate UTR Blocked: This transaction reference has already been utilized.' });
      }

      // Check if already in pending queue
      if ((db.pendingPosts || []).some(p => p.utr === cleanUtr)) {
        return sendJson(res, 409, { error: 'UTR Already In Queue: This request is already awaiting admin verification.' });
      }

      const newPost = {
        id: 'post_' + Date.now(),
        driverId: driverId || '9864012345',
        driverName: driverName || 'Driver',
        vehicleNo: (vehicleNo || 'AS 02 ER 0000').toUpperCase(),
        type: type || 'erickshaw',
        utr: cleanUtr,
        fee: 100,
        photo: photo || 'https://images.unsplash.com/photo-1544005313-94ddf0286df2?w=150',
        stand: stand || 'Station Stand',
        lat: Number(lat) || 26.3465,
        lng: Number(lng) || 92.6815,
        submittedAt: new Date().toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' }) + ' (Today)',
        status: 'pending_approval'
      };

      db.pendingPosts.push(newPost);
      writeDb(db);

      return sendJson(res, 201, {
        success: true,
        message: 'Submitted to server verification queue',
        post: newPost
      });
    } catch (e) {
      return sendJson(res, 400, { error: e.message });
    }
  }

  // 6. Driver Check Approval Status (GET /api/driver/status?utr=...&vehicleNo=...)
  if (pathname === '/api/driver/status' && req.method === 'GET') {
    const query = parsedUrl.query;
    const utr = (query.utr || '').trim();
    const vehicleNo = (query.vehicleNo || '').trim().toUpperCase();

    const db = readDb();
    const isApproved = (db.activeDrivers || []).some(d => 
      (d.vehicleNo && d.vehicleNo.toUpperCase() === vehicleNo) ||
      (utr && (db.usedUtrs || []).includes(utr))
    );

    return sendJson(res, 200, {
      approved: isApproved,
      activeDriversCount: (db.activeDrivers || []).length
    });
  }

  // 7. Public Sanitized Active Drivers (GET /api/public/drivers)
  // Strips sensitive PII (no phone numbers or bank details sent to public passenger map)
  if (pathname === '/api/public/drivers' && req.method === 'GET') {
    const db = readDb();
    const now = Date.now();
    const sanitizedDrivers = (db.activeDrivers || [])
      .filter(d => !d.expiresAt || d.expiresAt > now) // Only active non-expired vehicles
      .map(d => ({
        id: d.id,
        name: d.name,
        vehicleNo: d.vehicleNo,
        photo: d.photo,
        stand: d.stand,
        lat: d.lat,
        lng: d.lng,
        fare: d.fare || 15,
        battery: d.battery || '90%',
        rating: d.rating || 4.9,
        dutyStatus: d.dutyStatus || 'on_duty'
      }));

    return sendJson(res, 200, {
      drivers: sanitizedDrivers,
      count: sanitizedDrivers.length
    });
  }

  // --- STATIC FILE SERVING FOR SINGLE PAGE APP ---
  let requestedPath = pathname === '/' ? '/index.html' : pathname;
  // Prevent directory traversal attacks
  const safePath = path.normalize(requestedPath).replace(/^(\.\.[\/\\])+/, '');
  const filePath = path.join(__dirname, safePath);
  const ext = path.extname(filePath).toLowerCase();
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';

  fs.readFile(filePath, (err, content) => {
    if (err) {
      if (err.code === 'ENOENT') {
        // Fallback to index.html for client-side routing
        fs.readFile(path.join(__dirname, 'index.html'), (e, indexContent) => {
          if (e) {
            res.writeHead(404, { 'Content-Type': 'text/plain' });
            res.end('404 Not Found');
          } else {
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
            res.end(indexContent);
          }
        });
      } else {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('Server Error: ' + err.code);
      }
    } else {
      res.writeHead(200, {
        'Content-Type': contentType,
        'Access-Control-Allow-Origin': '*'
      });
      res.end(content);
    }
  });
});

server.listen(PORT, () => {
  ensureDbExists();
  initAdminCredentials();
  console.log(`================================================================`);
  console.log(` SafarSaathi Production Enterprise Server`);
  console.log(` Listening on: http://localhost:${PORT}`);
  console.log(` Security Mode: Salted Scrypt + HMAC-SHA256 Session Tokens`);
  console.log(` Authoritative DB: ${DB_FILE}`);
  console.log(`================================================================`);
});
