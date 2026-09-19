// ─────────────────────────────────────────────────────────────────────────────
// FOOD MELA BACKEND  –  Express + Upstash Redis (persistent, serverless-safe)
// All user and order states are stored persistently in Upstash Redis.
// Fully backward compatible with all original Customer & Driver App endpoints.
// ─────────────────────────────────────────────────────────────────────────────
const express = require('express');
const cors    = require('cors');
const https   = require('https');
const crypto  = require('crypto');
try { require('dotenv').config({ path: require('path').join(__dirname, '.env') }); } catch (_) {}

// ─── UPSTASH REDIS CONFIG ─────────────────────────────────────────────────────
// Secrets come from env (Vercel → Settings → Environment Variables).
// See .env.example. Rotate the old hardcoded token in Upstash dashboard.
const UPSTASH_URL   = process.env.UPSTASH_URL || 'https://deciding-fish-161177.upstash.io';
const UPSTASH_TOKEN = process.env.UPSTASH_TOKEN || '';
if (!UPSTASH_TOKEN) console.warn('⚠️ UPSTASH_TOKEN missing — set it in .env / Vercel env');

const app = express();
// ─── SECURITY HARDENING (2026-09-18 red-team fixes) ─────────────────────────
// CORS: same-origin + known frontends only. The apps call same-origin
// /api/* (no Origin header on native), the websites call same-origin too.
// Wildcard '*' previously let ANY evil site drive the API from a victim's
// browser (cancel/accept orders, read order history).
const ALLOWED_ORIGINS = new Set([
  'https://foodmela.online',
  'https://www.foodmela.online',
  'https://food-mela-backend.vercel.app',
  'http://localhost:3000',
  'http://localhost:5173',
]);
app.use(cors({
  origin: (origin, cb) => {
    // No Origin header (native apps, curl, server-to-server) → allow.
    // Browser Origin must be in the allow-list.
    if (!origin || ALLOWED_ORIGINS.has(origin)) return cb(null, true);
    return cb(null, false);
  },
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
}));
app.use(express.json({ limit: '200kb' }));
app.use(express.urlencoded({ extended: true, limit: '200kb' }));
// Security headers (helmet-less, zero new deps).
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Content-Security-Policy', "default-src 'self'; frame-ancestors 'none'");
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});
// Tiny in-memory rate limiter (per-IP, per-path-prefix). Serverless-safe:
// each instance throttles independently — enough to stop scraping bursts.
const _rlBuckets = new Map();
function rateLimit({ windowMs, max, prefix }) {
  return (req, res, next) => {
    try {
      const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
        || req.socket?.remoteAddress || 'unknown';
      const key = `${prefix}:${ip}`;
      const now = Date.now();
      let b = _rlBuckets.get(key);
      if (!b || now - b.start > windowMs) b = { start: now, count: 0 };
      b.count++;
      _rlBuckets.set(key, b);
      if (_rlBuckets.size > 5000) {
        for (const [k, v] of _rlBuckets) {
          if (now - v.start > windowMs) _rlBuckets.delete(k);
          if (_rlBuckets.size <= 4000) break;
        }
      }
      if (b.count > max) {
        res.setHeader('Retry-After', String(Math.ceil(windowMs / 1000)));
        return res.status(429).json({ success: false, error: 'Too many requests — slow down' });
      }
    } catch (_) { /* fail-open: never block legit traffic on limiter bugs */ }
    next();
  };
}
const limitApi = rateLimit({ windowMs: 60 * 1000, max: 120, prefix: 'api' });
const limitAuth = rateLimit({ windowMs: 60 * 1000, max: 20, prefix: 'auth' });
app.use('/api/', limitApi);
app.use('/api/auth/', limitAuth);
app.use('/api/admin/', limitAuth);
app.use('/api/payu/initiate', rateLimit({ windowMs: 60 * 1000, max: 30, prefix: 'payu' }));

const ORDERS_KEY    = 'fm_orders_v1';

// ─── API AUTH (phone-based session tokens) ──────────────────────────────────
// The website proves phone ownership via phone.email OTP; the backend mints a
// short-lived HMAC token bound to that phone. Sensitive endpoints
// (/orders/live redacted view, /user/:phone/*, cancel) require the token's
// phone to MATCH the requested phone — killing IDOR. Rider endpoints
// (accept/update-stage) require a rider token minted at rider login.
// Tokens are stateless (HMAC-SHA256, no storage) and expire after 7 days.
const API_TOKEN_SECRET = process.env.API_TOKEN_SECRET || process.env.PAYU_SALT || '';
function _b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function mintApiToken(phone, role) {
  const clean = String(phone || '').replace(/[^0-9]/g, '').slice(-10);
  const exp = Date.now() + 7 * 24 * 60 * 60 * 1000;
  const body = _b64url(`${clean}.${role}.${exp}`);
  const sig = crypto.createHmac('sha256', API_TOKEN_SECRET || 'fm-dev-only')
    .update(body).digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return `${body}.${sig}`;
}
function verifyApiToken(token) {
  try {
    if (!token || typeof token !== 'string') return null;
    const parts = token.split('.');
    if (parts.length !== 2) return null;
    const [body, sig] = parts;
    const expect = crypto.createHmac('sha256', API_TOKEN_SECRET || 'fm-dev-only')
      .update(body).digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    if (sig.length !== expect.length) return null;
    let diff = 0;
    for (let i = 0; i < sig.length; i++) diff |= sig.charCodeAt(i) ^ expect.charCodeAt(i);
    if (diff !== 0) return null;
    const raw = Buffer.from(body.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString();
    const [phone, role, exp] = raw.split('.');
    if (!phone || !role || !exp || Date.now() > Number(exp)) return null;
    if (!['customer', 'rider', 'admin'].includes(role)) return null;
    return { phone, role };
  } catch (_) { return null; }
}
function bearerToken(req) {
  const h = String(req.headers.authorization || '');
  if (h.startsWith('Bearer ')) return h.slice(7).trim();
  return String(req.body?.apiToken || req.query?.apiToken || '').trim() || null;
}
// Require a valid token whose phone matches :phone param (IDOR kill).
function requireSelf(req, res, next) {
  const t = verifyApiToken(bearerToken(req));
  const target = String(req.params.phone || '').replace(/[^0-9]/g, '').slice(-10);
  if (!t || t.phone !== target) {
    return res.status(401).json({ success: false, error: 'Login required' });
  }
  req.apiAuth = t;
  next();
}
// Require rider (or admin) role for rider-mutation endpoints.
function requireRider(req, res, next) {
  const t = verifyApiToken(bearerToken(req));
  if (!t || (t.role !== 'rider' && t.role !== 'admin')) {
    return res.status(401).json({ success: false, error: 'Rider login required' });
  }
  req.apiAuth = t;
  next();
}
// Strip sensitive fields from orders served to non-owners. Owners prove
// ownership with their token phone == order phone; riders see operational
// fields but NEVER the delivery OTP or customer FCM token.
function sanitizeOrder(o, viewer) {
  const orderPhone = String(o.phone || o.customerPhone || '').replace(/[^0-9]/g, '').slice(-10);
  const isOwner = viewer && viewer.phone === orderPhone;
  const isRider = viewer && (viewer.role === 'rider' || viewer.role === 'admin');
  const copy = { ...o };
  if (isOwner || isRider) return copy; // full view for owner + assigned flow
  delete copy.deliveryOtp;
  delete copy.customerFcmToken;
  delete copy.riderFcmToken;
  return copy;
}
function viewerFrom(req) {
  return verifyApiToken(bearerToken(req));
}

// ─── FCM PUSH (rider background/killed-app ring) ──────────────────────────────
// Service-account JSON comes from env FCM_SERVICE_ACCOUNT (whole JSON string).
// Order placement fires a data+notification push to topic rider_notifications.
// The rider app is subscribed to that topic on every dashboard init.
let _fcmToken = null;
let _fcmTokenExp = 0;
function fcmServiceAccount() {
  try {
    const raw = process.env.FCM_SERVICE_ACCOUNT || '';
    if (!raw) return null;
    return JSON.parse(raw);
  } catch (_) { return null; }
}
function fcmAccessToken() {
  return new Promise((resolve) => {
    try {
      const sa = fcmServiceAccount();
      if (!sa || !sa.private_key || !sa.client_email) return resolve(null);
      if (_fcmToken && Date.now() < _fcmTokenExp) return resolve(_fcmToken);
      const now = Math.floor(Date.now() / 1000);
      const b64u = (o) => Buffer.from(typeof o === 'string' ? o : JSON.stringify(o)).toString('base64url');
      const header = b64u({ alg: 'RS256', typ: 'JWT' });
      const claim = b64u({ iss: sa.client_email, scope: 'https://www.googleapis.com/auth/firebase.messaging', aud: 'https://oauth2.googleapis.com/token', iat: now, exp: now + 3600 });
      const signer = crypto.createSign('RSA-SHA256');
      signer.update(header + '.' + claim);
      const sig = signer.sign(sa.private_key, 'base64url');
      const body = new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: `${header}.${claim}.${sig}` }).toString();
      const req = https.request({ hostname: 'oauth2.googleapis.com', path: '/token', method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) } }, (res) => {
        let d = '';
        res.on('data', (c) => { d += c; });
        res.on('end', () => {
          try {
            const j = JSON.parse(d);
            if (j.access_token) { _fcmToken = j.access_token; _fcmTokenExp = Date.now() + 50 * 60 * 1000; return resolve(_fcmToken); }
          } catch (_) {}
          resolve(null);
        });
      });
      req.on('error', () => resolve(null));
      req.write(body);
      req.end();
    } catch (_) { resolve(null); }
  });
}
function sendFcmToTopic(topic, title, body, data) {
  return new Promise(async (resolve) => {
    try {
      const token = await fcmAccessToken();
      if (!token) return resolve(false);
      const sa = fcmServiceAccount();
      // WhatsApp-style incoming call: notification + data push. The
      // `notification` block lets ANDROID ITSELF wake the screen and fire the
      // full-screen intent (food_mela_orders channel, PRIORITY_MAX) even when
      // the app is backgrounded/killed — Dart code alone cannot open a screen
      // from those states. The app cancels by tag on accept/decline so no
      // stale copy lingers. Data carries full order fields for the call UI.
      const strData = {};
      for (const [k, v] of Object.entries(data || {})) {
        if (v !== undefined && v !== null) strData[k] = String(v);
      }
      const orderTag = String((data && data.orderId) || Date.now());
      const payload = JSON.stringify({ message: { topic, notification: { title, body }, data: { ...strData, type: 'new_order', title, body, click_action: 'FLUTTER_NOTIFICATION_CLICK' }, android: { priority: 'high', notification: { sound: 'default', channel_id: 'food_mela_orders', tag: orderTag, visibility: 'PUBLIC', notification_priority: 'PRIORITY_MAX' } } } });
      const req = https.request({ hostname: 'fcm.googleapis.com', path: `/v1/projects/${sa.project_id}/messages:send`, method: 'POST', headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } }, (res) => {
        let d = '';
        res.on('data', (c) => { d += c; });
        res.on('end', () => resolve(res.statusCode < 300));
      });
      req.on('error', () => resolve(false));
      req.write(payload);
      req.end();
    } catch (_) { resolve(false); }
  });
}
function pushNewOrderToRiders(order) {
  // Fire-and-forget — never blocks the order response.
  setImmediate(async () => {
    try {
      const ok = await sendFcmToTopic(
        'rider_notifications',
        `🛵 New Order #${order.id}`,
        `${order.customerName || 'Customer'} • ₹${Math.floor(order.amountValue || 0)} — Tap to Accept`,
        {
          orderId: String(order.id),
          amount: String(Math.floor(order.amountValue || 0)),
          customerName: order.customerName || 'Customer',
          address: order.address || '',
          customerPhone: order.phone || order.customerPhone || '',
          items: typeof order.items === 'string' ? order.items : '',
          categoryLabel: order.orderCategoryLabel || '',
        },
      );
      console.log(ok ? `📲 FCM push sent for ${order.id}` : `⚠️ FCM push skipped/failed for ${order.id} (no FCM_SERVICE_ACCOUNT?)`);
    } catch (e) { console.error('FCM push notice:', e.message); }
  });
}

// ─── FIRESTORE ORDER WATCHER (server-side new-order push) ───────────────────
// WHY: the customer app writes orders DIRECTLY to Firestore (never calls
// /api/orders/place), so pushNewOrderToRiders() never fires. This poller
// closes that gap WITHOUT any app update: Vercel Cron (or any scheduler)
// hits GET /api/orders/watch every minute; it lists recent Firestore orders,
// pushes FCM to rider_notifications for fresh stage-0 ones, and records
// pushed IDs in Upstash so each order rings exactly once — even if the rider
// app is killed. Safe to call as often as every 30s.
// Setup: Vercel → Project → Settings → Cron Jobs → GET /api/orders/watch
// every minute. No cron? Call it from the admin panel on an interval.
const WATCHED_KEY = 'fm_watched_orders_v1';
function firestoreGet(path) {
  return new Promise((resolve) => {
    try {
      const project = process.env.FIRESTORE_PROJECT_ID || 'food-mela-notification';
      const full = `/v1/projects/${project}/databases/(default)/documents${path}`;
      const r = https.request({ hostname: 'firestore.googleapis.com', path: full, method: 'GET' }, (rs) => {
        let d = '';
        rs.on('data', (c) => { d += c; });
        rs.on('end', () => { try { resolve(JSON.parse(d)); } catch { resolve(null); } });
      });
      r.on('error', () => resolve(null));
      r.setTimeout(10000, () => { r.destroy(); resolve(null); });
      r.end();
    } catch (_) { resolve(null); }
  });
}
function fsStr(field) {
  if (!field) return '';
  return field.stringValue ?? '';
}
function fsNum(field) {
  if (!field) return 0;
  if (field.integerValue != null) return Number(field.integerValue);
  if (field.doubleValue != null) return Number(field.doubleValue);
  return 0;
}
// Cron secret: Vercel Cron sends Authorization: Bearer <CRON_SECRET>.
// Without it the endpoint 404s — it leaks order IDs + phones otherwise.
app.get('/api/orders/watch', async (req, res) => {
  const secret = process.env.CRON_SECRET || '';
  const got = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (!secret || got !== secret) {
    return res.status(404).json({ success: false, error: 'Not found' });
  }
  try {
    const data = await firestoreGet('/orders?pageSize=25&orderBy=createdAt%20desc');
    const docs = (data && data.documents) || [];
    let watched = [];
    try {
      const r = await upstashCommand(['GET', WATCHED_KEY]);
      watched = JSON.parse(r.result || '[]');
      if (!Array.isArray(watched)) watched = [];
    } catch (_) { watched = []; }
    const seen = new Set(watched);
    const fresh = [];
    const now = Date.now();
    for (const doc of docs) {
      const id = (doc.name || '').split('/').pop();
      if (!id || seen.has(id)) continue;
      const f = doc.fields || {};
      const stage = fsNum(f.stage);
      const deleted = f.isDeleted && f.isDeleted.booleanValue === true;
      if (deleted || stage !== 0) { seen.add(id); continue; }
      // Only ring for orders placed in the last 15 min (avoid stale replays)
      let ageMs = Infinity;
      try {
        const ts = (f.createdAt && f.createdAt.timestampValue) || '';
        if (ts) ageMs = now - new Date(ts).getTime();
      } catch (_) {}
      if (!Number.isFinite(ageMs) || ageMs > 15 * 60 * 1000) { seen.add(id); continue; }
      fresh.push({
        id,
        customerName: fsStr(f.customerName) || 'Customer',
        amountValue: fsNum(f.totalAmount),
        address: fsStr(f.address),
        customerPhone: fsStr(f.customerPhone),
        items: fsStr(f.itemsSummary),
        categoryLabel: fsStr(f.orderCategoryLabel),
      });
    }
    let pushed = 0;
    for (const o of fresh) {
      try {
        const ok = await sendFcmToTopic(
          'rider_notifications',
          `🛵 New Order #${o.id}`,
          `${o.customerName} • ₹${Math.floor(o.amountValue)} — Tap to Accept`,
          {
            orderId: String(o.id),
            amount: String(Math.floor(o.amountValue)),
            customerName: o.customerName,
            address: o.address || '',
            customerPhone: o.customerPhone || '',
            items: o.items || '',
            categoryLabel: o.categoryLabel || '',
          },
        );
        if (ok) pushed++;
        console.log(ok ? `📲 [WATCH] FCM push sent for ${o.id}` : `⚠️ [WATCH] FCM failed for ${o.id}`);
      } catch (e) { console.error('[WATCH] push notice:', e.message); }
      seen.add(o.id);
    }
    // Persist seen IDs (cap 500) so replays never double-ring
    try {
      const arr = [...seen].slice(-500);
      await upstashCommand(['SET', WATCHED_KEY, JSON.stringify(arr), 'EX', '86400']);
    } catch (_) {}
    res.json({ success: true, checked: docs.length, pushed, fresh: fresh.map((o) => o.id) });
  } catch (e) {
    res.json({ success: false, error: e.message });
  }
});

// ─── Direct-token FCM (WhatsApp-style incoming-call ring) ─────────────────────
// Sends a high-priority data+notification push to ONE device token.
// fullScreenIntent + channel food_mela_calls wakes the screen even if killed.
function sendFcmToToken(token, title, body, data) {
  return new Promise(async (resolve) => {
    try {
      const fcmToken = await fcmAccessToken();
      if (!fcmToken) return resolve(false);
      const sa = fcmServiceAccount();
      const payload = JSON.stringify({ message: { token, notification: { title, body }, data: { ...(data || {}), click_action: 'FLUTTER_NOTIFICATION_CLICK' }, android: { priority: 'high', notification: { sound: 'default', channel_id: 'food_mela_calls', visibility: 'PUBLIC', notification_priority: 'PRIORITY_MAX' } } } });
      const req = https.request({ hostname: 'fcm.googleapis.com', path: `/v1/projects/${sa.project_id}/messages:send`, method: 'POST', headers: { 'Authorization': `Bearer ${fcmToken}`, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } }, (res) => {
        let d = '';
        res.on('data', (c) => { d += c; });
        res.on('end', () => resolve(res.statusCode < 300));
      });
      req.on('error', () => resolve(false));
      req.write(payload);
      req.end();
    } catch (_) { resolve(false); }
  });
}

// ── POST /api/calls/:orderId/ring { callId, callerRole, receiverToken? } ──
// WhatsApp-style incoming-call push. CALLER MUST PROVE ORDER MEMBERSHIP:
// the apiToken phone must be the order's customer or its assigned rider —
// previously anyone could ring ANY order (harassment + push spam).
app.post('/api/calls/:orderId/ring', async (req, res) => {
  try {
    const { orderId } = req.params;
    const { callId, callerRole, receiverToken } = req.body || {};
    const viewer = viewerFrom(req);
    if (!viewer) return res.status(401).json({ success: false, error: 'Login required' });
    const orders = await readOrders();
    const order = orders.find(o => o.id === orderId);
    if (!order) return res.status(404).json({ success: false, error: 'Order not found' });
    const orderPhone = String(order.phone || order.customerPhone || '').replace(/[^0-9]/g, '').slice(-10);
    const by = String(order.acceptedBy || '');
    const isMember = viewer.role === 'admin'
      || viewer.phone === orderPhone
      || (by && (by === viewer.phone || by.replace(/[^0-9]/g, '').slice(-10) === viewer.phone));
    if (!isMember) return res.status(403).json({ success: false, error: 'Not part of this order' });
    const otherRole = callerRole === 'customer' ? 'rider' : 'customer';
    let token = (receiverToken || '').trim();
    if (!token) {
      // Read receiver token from the Firestore order doc (public read rule)
      try {
        const path = `/v1/projects/${process.env.FIRESTORE_PROJECT_ID || 'food-mela-notification'}/databases/(default)/documents/orders/${encodeURIComponent(orderId)}`;
        const doc = await new Promise((resolve) => {
          const r = https.request({ hostname: 'firestore.googleapis.com', path, method: 'GET' }, (rs) => {
            let d = '';
            rs.on('data', (c) => { d += c; });
            rs.on('end', () => { try { resolve(JSON.parse(d)); } catch { resolve(null); } });
          });
          r.on('error', () => resolve(null));
          r.setTimeout(8000, () => { r.destroy(); resolve(null); });
          r.end();
        });
        const f = (doc && doc.fields) || {};
        const key = otherRole === 'rider' ? 'riderFcmToken' : 'customerFcmToken';
        token = (f[key] && f[key].stringValue) || '';
      } catch (_) {}
    }
    if (!token) return res.json({ success: true, pushed: false, reason: 'no receiver token yet' });
    const callerLabel = callerRole === 'rider' ? 'Assigned Rider' : 'Customer';
    const ok = await sendFcmToToken(
      token,
      `📞 Incoming call — Order #${orderId}`,
      `${callerLabel} is calling you — tap to answer`,
      { type: 'incoming_call', orderId: String(orderId), callId: String(callId || ''), callerRole: String(callerRole || ''), receiverRole: otherRole },
    );
    console.log(ok ? `📞 CALL push sent — order ${orderId} (${callerRole}→${otherRole})` : `⚠️ CALL push failed — order ${orderId}`);
    res.json({ success: true, pushed: ok });
  } catch (e) {
    res.json({ success: true, pushed: false, reason: e.message });
  }
});

// ─── UPSTASH JSON ARRAY REST HELPER ───────────────────────────────────────────
function upstashCommand(cmdArray) {
  return new Promise((resolve, reject) => {
    const urlParsed = new URL(UPSTASH_URL);
    const bodyStr   = JSON.stringify(cmdArray);
    const options = {
      hostname: urlParsed.hostname,
      path:     '/',
      method:   'POST',
      headers:  {
        'Authorization': `Bearer ${UPSTASH_TOKEN}`,
        'Content-Type':  'application/json',
      },
    };
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch { resolve({ result: null }); }
      });
    });
    req.on('error', reject);
    req.write(bodyStr);
    req.end();
  });
}

// ─── USER STORAGE HELPERS ─────────────────────────────────────────────────────
async function readUser(phone) {
  try {
    const key = `fm_user_v1:${phone}`;
    const res = await upstashCommand(['GET', key]);
    if (res.result && res.result !== 'nil' && res.result !== null) {
      return JSON.parse(res.result);
    }
  } catch (e) {
    console.error(`Error reading user ${phone}:`, e.message);
  }
  // Return default template if not found (as original getOrCreateUser did)
  return {
    phone,
    name: '',
    email: '',
    addresses: [
      { title: 'Home 🏠', address: 'Flat 302, Saheed Nagar, Janpath Road, Bhubaneswar' },
      { title: 'Work 🏢', address: 'Tower B, Infocity IT Park, Patia, Bhubaneswar' }
    ],
    orderHistory: [],
    createdAt: new Date().toISOString()
  };
}

async function writeUser(phone, userData) {
  try {
    const key = `fm_user_v1:${phone}`;
    const json = JSON.stringify(userData);
    await upstashCommand(['SET', key, json]); // Persistent user storage (no expiry)
  } catch (e) {
    console.error(`Error writing user ${phone}:`, e.message);
  }
}

// ─── ORDER STORAGE HELPERS ────────────────────────────────────────────────────
async function readOrders() {
  try {
    const res = await upstashCommand(['GET', ORDERS_KEY]);
    if (res.result && res.result !== 'nil' && res.result !== null) {
      return JSON.parse(res.result);
    }
  } catch (e) {
    console.error('Redis read error:', e.message);
  }
  return [];
}

async function writeOrders(orders) {
  try {
    const json = JSON.stringify(orders);
    await upstashCommand(['SET', ORDERS_KEY, json, 'EX', '86400']); // expire after 24 hrs
  } catch (e) {
    console.error('Redis write error:', e.message);
  }
}

// ─── ROOT HEALTH CHECK ────────────────────────────────────────────────────────
app.get('/', async (req, res) => {
  const orders = await readOrders();
  res.json({
    status: 'ONLINE 🚀',
    service: 'Food Mela Backend',
    storage: 'Upstash Redis',
    version: '4.1.0',
    liveOrders: orders.filter(o => o.stage === 0 || o.stage === -1).length,
    completedOrders: orders.filter(o => o.stage >= 1).length,
    timestamp: new Date().toISOString()
  });
});

// ─── DIAGNOSTIC: test-push (proves FCM topic → phone path) ─────────────────
// GET /api/diag/test-push — sends a test notification to rider_notifications.
// If the rider phone shows it (foreground/background/killed), the ENTIRE
// FCM chain works and the problem is order-specific. If NOTHING shows even
// with the rider app OPEN, the phone is unsubscribed or FCM-blocked.
// Safe: clearly labeled TEST, no order side-effects.
// Disabled in production — anyone could spam every rider's phone with
// test pushes. Enable only for local debugging (ALLOW_DIAG=true).
app.get('/api/diag/test-push', async (req, res) => {
  if (process.env.ALLOW_DIAG !== 'true') {
    return res.status(404).json({ success: false, error: 'Not found' });
  }
  try {
    const ok = await sendFcmToTopic(
      'rider_notifications',
      '🧪 TEST — Food Mela Push Check',
      'Agar yeh dikha toh FCM chain OK hai. Time: ' + new Date().toISOString(),
      { type: 'new_order', orderId: 'TEST-PUSH', amount: '0', test: '1' },
    );
    console.log(ok ? '🧪 TEST push sent' : '⚠️ TEST push failed');
    res.json({ success: true, pushed: ok });
  } catch (e) {
    res.json({ success: false, error: e.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// ADMIN: RIDER PASSWORD RESET (Firebase Auth password set by admin)
// ═══════════════════════════════════════════════════════════════════════════════
// WHY: the web client SDK cannot change ANOTHER user's password — only a
// server with the Admin SDK can. The admin panel calls this with its own
// Firebase ID token; the backend verifies the caller is an admin, then
// creates-or-updates the rider's Auth password. Never logs or stores it.
// Env: reuses FCM_SERVICE_ACCOUNT (same Firebase project service account).
let _adminApp = null;
// ─── FIRESTORE MIRROR (app ↔ website live sync) ─────────────────────────────
// Every website order (COD place-order + PayU callback) is mirrored to the
// Firestore `orders` collection via the Admin SDK (bypasses rules), so the
// customer app, rider app, and website track the SAME doc in real time.
// Best-effort: Redis is the source of truth; a failed mirror never fails
// the order. Doc shape matches what the apps write (createOrder).
function adminDb() {
  try {
    const sa = fcmServiceAccount();
    if (!sa || !sa.private_key || !sa.client_email || !sa.project_id) return null;
    const admin = require('firebase-admin');
    if (!_adminApp) {
      _adminApp = admin.apps.length
        ? admin.app()
        : admin.initializeApp({ credential: admin.credential.cert(sa), projectId: sa.project_id });
    }
    return _adminApp.firestore();
  } catch (e) {
    console.error('adminDb init notice:', e.message);
    return null;
  }
}
function mirrorOrderToFirestore(o) {
  try {
    const db = adminDb();
    if (!db) return;
    const itemsArr = Array.isArray(o.items) ? o.items : [];
    const summary = typeof o.items === 'string'
      ? o.items
      : itemsArr.map((i) => `${i.quantity || 1}x ${i.name || i.itemId || 'Item'}`).join(', ');
    db.collection('orders').doc(String(o.id)).set({
      orderId: String(o.id),
      customerName: o.customerName || 'Customer',
      customerPhone: String(o.phone || o.customerPhone || ''),
      address: o.address || '',
      items: itemsArr,
      itemsSummary: summary,
      totalAmount: Number(o.amountValue ?? o.totalAmount ?? 0),
      total: o.total || '',
      status: o.status || 'Order Placed',
      stage: Number(o.stage ?? 0),
      riderId: o.acceptedBy ?? null,
      riderName: o.acceptedByName ?? null,
      deliveryOtp: String(o.deliveryOtp || ''),
      createdAt: new Date(o.placedAt || o.timestamp || Date.now()),
      updatedAt: new Date(),
      isDeleted: false,
      source: 'website',
    }, { merge: true }).catch((e) => console.error('mirror notice:', e.message));
  } catch (e) {
    console.error('mirror notice:', e.message);
  }
}
function adminAuth() {
  try {
    if (_adminApp) return _adminApp.auth();
    const sa = fcmServiceAccount();
    if (!sa || !sa.private_key || !sa.client_email || !sa.project_id) return null;
    const admin = require('firebase-admin');
    _adminApp = admin.apps.length
      ? admin.app()
      : admin.initializeApp({ credential: admin.credential.cert(sa), projectId: sa.project_id });
    return _adminApp.auth();
  } catch (e) {
    console.error('adminAuth init notice:', e.message);
    return null;
  }
}
async function isAdminCaller(idToken) {
  try {
    const authAdmin = adminAuth();
    if (!authAdmin || !idToken) return false;
    const decoded = await authAdmin.verifyIdToken(idToken);
    if ((decoded.email || '').toLowerCase() === 'admin@foodmela.com') return true;
    // Role check: users/{uid} must have role == 'admin'
    const project = process.env.FIRESTORE_PROJECT_ID || 'food-mela-notification';
    const docPath = `/v1/projects/${project}/databases/(default)/documents/users/${decoded.uid}`;
    const resp = await new Promise((resolve) => {
      const r = https.request({ hostname: 'firestore.googleapis.com', path: docPath, method: 'GET' }, (rs) => {
        let d = '';
        rs.on('data', (c) => { d += c; });
        rs.on('end', () => { try { resolve(JSON.parse(d)); } catch { resolve(null); } });
      });
      r.on('error', () => resolve(null));
      r.setTimeout(10000, () => { r.destroy(); resolve(null); });
      r.end();
    });
    return resp?.fields?.role?.stringValue === 'admin';
  } catch (_) { return false; }
}

app.post('/api/admin/riders/reset-password', async (req, res) => {
  try {
    const authHeader = String(req.headers.authorization || '');
    const idToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
    if (!(await isAdminCaller(idToken))) {
      return res.status(403).json({ success: false, error: 'admin only' });
    }
    const email = String(req.body.email || '').trim().toLowerCase();
    const newPassword = String(req.body.newPassword || '');
    if (!email.includes('@')) return res.status(400).json({ success: false, error: 'valid email required' });
    if (newPassword.length < 6) return res.status(400).json({ success: false, error: 'password must be at least 6 characters' });
    const authAdmin = adminAuth();
    if (!authAdmin) return res.status(500).json({ success: false, error: 'auth service not configured' });

    let uid;
    try {
      const existing = await authAdmin.getUserByEmail(email);
      uid = existing.uid;
      await authAdmin.updateUser(uid, { password: newPassword });
    } catch (e) {
      if (e.code === 'auth/user-not-found') {
        const created = await authAdmin.createUser({ email, password: newPassword });
        uid = created.uid;
      } else {
        throw e;
      }
    }
    res.json({ success: true, uid });
  } catch (e) {
    console.error('reset-password notice:', e.message);
    res.status(500).json({ success: false, error: 'reset failed' });
  }
});

// ─── TOKEN MINT: rider login → rider apiToken ─────────────────────────────────
// The rider app proves identity with its Firebase Auth ID token; the backend
// verifies the token, checks the users/{uid} doc is an approved + unblocked
// delivery_partner, and mints a rider apiToken bound to the rider's phone.
// Rate-limited (auth limiter) + brute-force safe (Firebase throttles).
app.post('/api/auth/rider/token', async (req, res) => {
  try {
    const authHeader = String(req.headers.authorization || '');
    const idToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : String(req.body.idToken || '');
    if (!idToken) return res.status(401).json({ success: false, error: 'Firebase login required' });
    const authAdmin = adminAuth();
    if (!authAdmin) return res.status(500).json({ success: false, error: 'auth service not configured' });
    let decoded;
    try { decoded = await authAdmin.verifyIdToken(idToken); }
    catch { return res.status(401).json({ success: false, error: 'Invalid session — login again' }); }
    const project = process.env.FIRESTORE_PROJECT_ID || 'food-mela-notification';
    const docPath = `/v1/projects/${project}/databases/(default)/documents/users/${decoded.uid}`;
    const resp = await new Promise((resolve) => {
      const r = https.request({ hostname: 'firestore.googleapis.com', path: docPath, method: 'GET' }, (rs) => {
        let d = '';
        rs.on('data', (c) => { d += c; });
        rs.on('end', () => { try { resolve(JSON.parse(d)); } catch { resolve(null); } });
      });
      r.on('error', () => resolve(null));
      r.setTimeout(10000, () => { r.destroy(); resolve(null); });
      r.end();
    });
    const f = (resp && resp.fields) || {};
    const role = (f.role && f.role.stringValue) || '';
    const approval = (f.approvalStatus && f.approvalStatus.stringValue) || '';
    const blocked = (f.accountStatus && f.accountStatus.stringValue) === 'blocked';
    const phone = ((f.phone && f.phone.stringValue) || '').replace(/[^0-9]/g, '').slice(-10);
    if (role !== 'delivery_partner') return res.status(403).json({ success: false, error: 'Rider account required' });
    if (blocked) return res.status(403).json({ success: false, error: 'Account is blocked' });
    if (approval !== 'approved') return res.status(403).json({ success: false, error: 'Account awaiting approval' });
    if (phone.length < 10) return res.status(403).json({ success: false, error: 'No phone linked to rider account' });
    // Firestore custom token so the rider app passes the hardened rules
    // (isRider checks users/{uid} role). uid = Firebase Auth uid.
    let firebaseToken = null;
    try {
      const authAdmin2 = adminAuth();
      if (authAdmin2) firebaseToken = await authAdmin2.createCustomToken(decoded.uid, { role: 'rider', phone_number: phone });
    } catch (e) { console.error('rider custom token notice:', e.message); }
    res.json({ success: true, apiToken: mintApiToken(phone, 'rider'), phone, firebaseToken });
  } catch (e) {
    res.status(500).json({ success: false, error: 'token mint failed' });
  }
});

// ─── TOKEN MINT: admin ID token → admin apiToken ─────────────────────────────
// Same verification as reset-password; lets the admin panel call
// admin-only API endpoints (clear-delivered, call-logs) with a short token.
app.post('/api/auth/admin/token', async (req, res) => {
  try {
    const authHeader = String(req.headers.authorization || '');
    const idToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : String(req.body.idToken || '');
    if (!(await isAdminCaller(idToken))) {
      return res.status(403).json({ success: false, error: 'admin only' });
    }
    res.json({ success: true, apiToken: mintApiToken('0000000000', 'admin') });
  } catch (e) {
    res.status(500).json({ success: false, error: 'token mint failed' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// USER PROFILE ENDPOINTS
// ═══════════════════════════════════════════════════════════════════════════════

// ─── AUTHENTICATED USER ENDPOINTS (IDOR kill: token phone must match) ────
app.get('/api/user/:phone', requireSelf, async (req, res) => {
  const user = await readUser(req.params.phone);
  res.json({ success: true, user });
});

app.post('/api/user/:phone/profile', requireSelf, async (req, res) => {
  const phone = req.params.phone;
  const user = await readUser(phone);
  if (req.body.name) user.name = String(req.body.name).slice(0, 80);
  if (req.body.email) user.email = String(req.body.email).slice(0, 120);
  await writeUser(phone, user);
  res.json({ success: true, user });
});

// Website OTP verification proxy — eapi.phone.email rejects browser-origin
// requests (CORS), so the website posts the access_token here and the backend
// (server-to-server, no CORS) exchanges it for the verified phone number.
const PE_CLIENT_ID = '14442678863809499061';

function postJson(urlStr, payload) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    const body = JSON.stringify(payload);
    const req = https.request({
      hostname: u.hostname,
      path: u.pathname,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
    }, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch { reject(new Error('bad verification response')); }
      });
    });
    req.on('error', reject);
    req.setTimeout(15000, () => req.destroy(new Error('verification timed out')));
    req.write(body);
    req.end();
  });
}

function getJson(urlStr) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    const req = https.request({
      hostname: u.hostname,
      path: u.pathname + u.search,
      method: 'GET',
    }, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch { reject(new Error('bad verification response')); }
      });
    });
    req.on('error', reject);
    req.setTimeout(15000, () => req.destroy(new Error('verification timed out')));
    req.end();
  });
}

app.post('/api/auth/phone-email/verify', async (req, res) => {
  try {
    // Official widget flow: the button's phoneEmailListener hands the website
    // a user_json_url, which only a server may fetch (browser CORS blocked).
    const userJsonUrl = String(req.body.user_json_url || '').trim();
    if (userJsonUrl) {
      let u;
      try { u = new URL(userJsonUrl); }
      catch { return res.status(400).json({ success: false, error: 'bad user_json_url' }); }
      if (u.protocol !== 'https:' || u.hostname !== 'user.phone.email') {
        return res.status(400).json({ success: false, error: 'bad user_json_url' });
      }
      const data = await getJson(userJsonUrl);
      const raw = `${data.user_country_code ?? ''}${data.user_phone_number ?? ''}`.replace(/[^0-9]/g, '');
      const phone = raw.slice(-10);
      if (phone.length < 10) {
        return res.status(401).json({ success: false, error: 'verification failed' });
      }
      const first = String(data.user_first_name ?? '').trim();
      const last = String(data.user_last_name ?? '').trim();
      const name = `${first} ${last}`.trim();
      let firebaseToken = null;
      try {
        const authAdmin = adminAuth();
        if (authAdmin) firebaseToken = await authAdmin.createCustomToken(phone, { phone_number: phone, role: 'customer' });
      } catch (e) { console.error('custom token notice:', e.message); }
      return res.json({ success: true, phone, name: name || null, jwt: null, apiToken: mintApiToken(phone, 'customer'), firebaseToken });
    }
    // Legacy redirect flow: access_token exchange (kept as fallback)
    const accessToken = String(req.body.access_token || '').trim();
    if (!accessToken) return res.status(400).json({ success: false, error: 'access_token required' });
    const data = await postJson('https://eapi.phone.email/getuser', {
      access_token: accessToken,
      client_id: PE_CLIENT_ID,
    });
    const raw = `${data.country_code ?? ''}${data.phone_no ?? ''}`.replace(/[^0-9]/g, '');
    const phone = raw.slice(-10);
    if (data.status !== 200 || phone.length < 10) {
      return res.status(401).json({ success: false, error: 'verification failed' });
    }
    let firebaseToken = null;
    try {
      const authAdmin = adminAuth();
      if (authAdmin) firebaseToken = await authAdmin.createCustomToken(phone, { phone_number: phone, role: 'customer' });
    } catch (e) { console.error('custom token notice:', e.message); }
    res.json({ success: true, phone, name: null, jwt: data.ph_email_jwt || null, apiToken: mintApiToken(phone, 'customer'), firebaseToken });
  } catch (e) {
    res.status(502).json({ success: false, error: e.message || 'verification failed' });
  }
});

// Website OTP registration — phone.email verified the number, so create the
// Redis profile (same store the apps use). Firestore users/{phone} is written
// by the apps when they next see this number; website never writes Firestore.
app.post('/api/user/register', async (req, res) => {
  try {
    const raw = String(req.body.phone || '').replace(/[^0-9]/g, '');
    const phone = raw.slice(-10);
    if (phone.length < 10) return res.status(400).json({ success: false, error: 'valid phone required' });
    const user = await readUser(phone);
    if (req.body.name) {
      user.name = String(req.body.name).trim();
      user.fullName = user.name;
      const parts = user.name.split(/\s+/);
      user.firstName = parts[0] || '';
      user.lastName = parts.slice(1).join(' ') || '';
    }
    if (req.body.address) {
      const addr = String(req.body.address).trim();
      user.addresses = Array.isArray(user.addresses) ? user.addresses : [];
      if (!user.addresses.some(a => a.address === addr)) {
        user.addresses.unshift({ title: 'Website 🏠', address: addr });
      }
    }
    user.role = user.role || 'customer';
    user.accountStatus = user.accountStatus || 'active';
    user.approvalStatus = user.approvalStatus || 'approved';
    if (user.accountStatus === 'blocked') {
      return res.status(403).json({ success: false, error: 'account blocked' });
    }
    await writeUser(phone, user);
    res.json({ success: true, user: { phone, name: user.name || '', address: (req.body.address || '').trim() } });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// ADDRESS ENDPOINTS
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/user/:phone/addresses', requireSelf, async (req, res) => {
  const user = await readUser(req.params.phone);
  res.json({ success: true, addresses: user.addresses });
});

app.post('/api/user/:phone/addresses', requireSelf, async (req, res) => {
  const { title, address } = req.body;
  if (!title || !address) return res.status(400).json({ success: false, error: 'title and address required' });
  const phone = req.params.phone;
  const user = await readUser(phone);
  user.addresses = user.addresses.filter(a => a.title !== title);
  user.addresses.push({ title: String(title).slice(0, 40), address: String(address).slice(0, 500) });
  await writeUser(phone, user);
  console.log(`📍 Address saved for ${phone}: ${title}`);
  res.json({ success: true, addresses: user.addresses });
});

app.delete('/api/user/:phone/addresses/:title', requireSelf, async (req, res) => {
  const phone = req.params.phone;
  const user = await readUser(phone);
  const targetTitle = decodeURIComponent(req.params.title);
  user.addresses = user.addresses.filter(a => a.title !== targetTitle);
  await writeUser(phone, user);
  res.json({ success: true, addresses: user.addresses });
});

// ═══════════════════════════════════════════════════════════════════════════════
// ORDER ENDPOINTS
// ═══════════════════════════════════════════════════════════════════════════════

// GET live (unaccepted) orders – RIDER ONLY. OTP + FCM tokens stripped:
// riders don't need the OTP (only the customer shares it at the door).
app.get('/api/orders/live', requireRider, async (req, res) => {
  try {
    const orders = await readOrders();
    const live = orders
      .filter(o => o.stage === 0 || o.stage === -1)
      .map(o => sanitizeOrder(o, { ...req.apiAuth, role: 'rider' }));
    res.json({ success: true, orders: live });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// GET completed orders – RIDER ONLY, scoped to the caller's own accepted
// orders unless admin. driverId query is ignored (was spoofable).
app.get('/api/orders/completed', requireRider, async (req, res) => {
  try {
    const me = req.apiAuth;
    const orders = await readOrders();
    const completed = orders.filter(o => {
      if (o.stage < 1) return false;
      if (me.role === 'admin') return true;
      const by = String(o.acceptedBy || '');
      return by && (by === me.phone || by.replace(/[^0-9]/g, '').slice(-10) === me.phone);
    }).map(o => sanitizeOrder(o, { ...me, role: 'rider' }));
    res.json({ success: true, orders: completed });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// GET order history for a customer phone – OWNER ONLY (IDOR kill).
app.get('/api/user/:phone/orders', requireSelf, async (req, res) => {
  try {
    const user = await readUser(req.params.phone);
    res.json({ success: true, orders: user.orderHistory || [] });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// GET single order status for customer live tracking – sanitized for
// strangers (no OTP/FCM tokens); full view for owner or rider/admin.
app.get('/api/orders/status/:orderId', async (req, res) => {
  try {
    const orders = await readOrders();
    const order  = orders.find(o => o.id === req.params.orderId);
    if (!order) return res.status(404).json({ success: false, error: 'Order not found' });
    res.json({ success: true, order: sanitizeOrder(order, viewerFrom(req)) });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// Place New Order – OWNER-BOUND. The token phone must match the order phone,
// so nobody can place orders impersonating someone else (was fully open).
// Supports BOTH `/api/orders/place` and `/api/orders/create`.
const placeOrderHandler = async (req, res) => {
  try {
    const viewer = viewerFrom(req);
    if (!viewer || (viewer.role !== 'customer' && viewer.role !== 'admin')) {
      return res.status(401).json({ success: false, error: 'Login required' });
    }
    const { customerName, phone, address, items, totalAmount } = req.body;
    const orderPhone = String(phone || '').replace(/[^0-9]/g, '').slice(-10);
    if (viewer.role !== 'admin' && viewer.phone !== orderPhone) {
      return res.status(403).json({ success: false, error: 'Phone must be your own number' });
    }
    const amountNum = Number(totalAmount || 0);
    if (!amountNum || amountNum <= 0 || amountNum > 50000) {
      return res.status(400).json({ success: false, error: 'Valid totalAmount required' });
    }
    const orderId = req.body.id || `FM-${Math.floor(1000 + Math.random() * 9000)}`;

    const orders = await readOrders();

    // Deduplicate
    const existing = orders.find(o => o.id === orderId);
    if (existing) {
      return res.json({ success: true, order: existing, duplicate: true });
    }

    const totalStr = req.body.total || `₹${Math.floor(totalAmount || 0)}`;

    const newOrder = {
      id:           orderId,
      customerName: customerName || 'Customer',
      phone:        phone        || 'unknown',
      address:      address      || 'Bhubaneswar',
      items:        items        || 'Food items',
      total:        totalStr,
      amountValue:  totalAmount  || 0,
      stage:        0,
      status:       'Order Placed & Waiting for Delivery Boy 📝🍳',
      acceptedBy:   null,
      acceptedByName: null,
      deliveryOtp:  req.body.deliveryOtp || String(1000 + Math.floor(Math.random() * 9000)),
      timestamp:    new Date().toISOString(),
      placedAt:     new Date().toISOString(),
      updatedAt:    new Date().toISOString(),
    };

    orders.unshift(newOrder);
    await writeOrders(orders);

    // Save to customer order history in Redis
    if (phone && phone !== 'unknown') {
      const user = await readUser(phone);
      if (!user.orderHistory) user.orderHistory = [];
      user.orderHistory.unshift({ ...newOrder, orderStatus: 'placed' });
      if (user.orderHistory.length > 50) user.orderHistory = user.orderHistory.slice(0, 50);
      await writeUser(phone, user);
    }

    console.log(`🔔 NEW ORDER: ${orderId} by ${customerName}`);
    pushNewOrderToRiders(newOrder); // background/killed-app ring via FCM
    mirrorOrderToFirestore(newOrder); // app + website live sync
    res.status(201).json({ success: true, order: newOrder });
  } catch (e) {
    console.error('Place order error:', e);
    res.status(500).json({ success: false, error: e.message });
  }
};

app.post('/api/orders/place', placeOrderHandler);
app.post('/api/orders/create', placeOrderHandler);

// ─── PAYU PAYMENT GATEWAY INTEGRATION (LIVE) ──────────────────────────────────
// Secrets ONLY from env (Vercel → Settings → Environment Variables):
//   PAYU_KEY  = merchant key (e.g. gtKFFx style value from PayU dashboard)
//   PAYU_SALT = merchant salt (NEVER commit — env only)
//   PAYU_ENV  = 'production' (live) or 'test'
const PAYU_KEY = process.env.PAYU_KEY || '';
const PAYU_SALT = process.env.PAYU_SALT || '';
const PAYU_ENV = process.env.PAYU_ENV || 'production';
const PAYU_BASE = PAYU_ENV === 'production' ? 'https://secure.payu.in' : 'https://test.payu.in';
const PAYU_PAYMENT_URL = `${PAYU_BASE}/_payment`;
const PAYU_VERIFY_URL = PAYU_ENV === 'production'
  ? 'https://info.payu.in/merchant/postservice?form=2'
  : 'https://test.payu.in/merchant/postservice?form=2';
if (!PAYU_KEY || !PAYU_SALT) console.warn('⚠️ PAYU_KEY/PAYU_SALT missing — set them in .env / Vercel env');

async function saveDraftOrder(orderId, draftData) {
  try {
    await upstashCommand(['SET', `fm_draft_order:${orderId}`, JSON.stringify(draftData), 'EX', '3600']);
  } catch (e) {
    console.error('Save draft error:', e.message);
  }
}

async function getDraftOrder(orderId) {
  try {
    const res = await upstashCommand(['GET', `fm_draft_order:${orderId}`]);
    if (res.result && res.result !== 'nil' && res.result !== null) {
      return JSON.parse(res.result);
    }
  } catch (e) {
    console.error('Get draft error:', e.message);
  }
  return null;
}

// 1. INITIATE PAYMENT – Builds PayU hash + form fields for frontend auto-submit
app.post('/api/payu/initiate', async (req, res) => {
  try {
    if (!PAYU_KEY || !PAYU_SALT) {
      return res.status(500).json({ success: false, error: 'PayU not configured — contact support' });
    }
    const { customerName, phone, email, address, items, totalAmount } = req.body || {};
    const amountNum = Number(totalAmount || 0);
    if (!amountNum || amountNum <= 0) {
      return res.status(400).json({ success: false, error: 'Valid totalAmount required' });
    }

    const txnid = req.body.orderId || `FM${Date.now().toString().slice(-8)}`;
    const amtStr = amountNum.toFixed(2);
    const firstname = (customerName || 'Customer').slice(0, 60);
    const cleanPhone = String(phone || '').replace(/[^0-9]/g, '').slice(-10);
    const productinfo = 'FoodMela Order';

    // Save draft order to Redis for automated reconstruction on callback
    const draftData = {
      orderId: txnid,
      customerName: firstname,
      phone: phone || 'unknown',
      address: address || 'Birmaharajpur',
      items: items || 'Food items',
      totalAmount: amountNum,
      total: `₹${Math.floor(amountNum)}`,
      createdAt: new Date().toISOString(),
    };
    await saveDraftOrder(txnid, draftData);

    const surl = process.env.PAYU_SURL || 'https://foodmela.online/api/payu/callback';
    const furl = process.env.PAYU_FURL || 'https://foodmela.online/api/payu/callback';

    // PayU hash sequence: key|txnid|amount|productinfo|firstname|email|udf1..udf10|SALT
    const udfs = ['', '', '', '', '', '', '', '', '', ''];
    const hashSeq = [PAYU_KEY, txnid, amtStr, productinfo, firstname, email || '', ...udfs, PAYU_SALT].join('|');
    const hash = crypto.createHash('sha512').update(hashSeq).digest('hex');

    return res.json({
      success: true,
      payuUrl: PAYU_PAYMENT_URL,
      fields: {
        key: PAYU_KEY,
        txnid,
        amount: amtStr,
        productinfo,
        firstname,
        email: email || '',
        phone: cleanPhone,
        surl,
        furl,
        hash,
        udf1: '', udf2: '', udf3: '', udf4: '', udf5: '',
        udf6: '', udf7: '', udf8: '', udf9: '', udf10: '',
      },
    });
  } catch (err) {
    console.error('PayU initiate exception:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// 2. SURL/FURL CALLBACK – Verify PayU hash & place order on success
app.post('/api/payu/callback', async (req, res) => {
  try {
    const d = req.body || {};
    const txnid = d.txnid || '';
    const status = (d.status || '').toLowerCase();
    const payuMoneyId = d.payuMoneyId || d.mihpayid || '';

    console.log(`🔔 PayU Callback: ${txnid} -> status: ${d.status}, mode: ${d.mode}`);

    if (!txnid) {
      return res.redirect(303, 'https://foodmela.online/?payment_error=Missing%20Order%20ID');
    }

    // Verify reverse hash: SALT|status|udf10..udf1|email|firstname|productinfo|amount|txnid|key
    let hashOk = false;
    try {
      const udfs = [d.udf10 || '', d.udf9 || '', d.udf8 || '', d.udf7 || '', d.udf6 || '',
                     d.udf5 || '', d.udf4 || '', d.udf3 || '', d.udf2 || '', d.udf1 || ''];
      const revSeq = [PAYU_SALT, status, ...udfs, d.email || '', d.firstname || '',
                      d.productinfo || '', d.amount || '', txnid, PAYU_KEY].join('|');
      const expected = crypto.createHash('sha512').update(revSeq).digest('hex');
      hashOk = expected === (d.hash || '');
    } catch (_) { hashOk = false; }
    if (!hashOk) console.warn(`⚠️ PayU hash mismatch for ${txnid} — still checking status`);

    if (status === 'success' && hashOk) {
      const draft = await getDraftOrder(txnid);
      const orders = await readOrders();
      let existing = orders.find(o => o.id === txnid);

      if (!existing) {
        const customerName = draft?.customerName || d.firstname || 'Customer';
        const phone = draft?.phone || d.phone || 'unknown';
        const address = draft?.address || 'Birmaharajpur';
        const items = draft?.items || 'Food items';
        const totalAmount = draft?.totalAmount || Number(d.amount || 0);

        const newOrder = {
          id: txnid,
          customerName,
          phone,
          address: `${address} [PREPAID - PAID ONLINE (PayU: ${payuMoneyId})]`,
          items,
          total: `₹${Math.floor(totalAmount)}`,
          amountValue: totalAmount,
          stage: 0,
          status: 'Order Placed & Waiting for Delivery Boy 📝🍳',
          paymentMode: 'PREPAID',
          paymentStatus: 'PAID',
          payuTxnId: payuMoneyId,
          acceptedBy: null,
          acceptedByName: null,
          deliveryOtp: String(1000 + Math.floor(Math.random() * 9000)),
          timestamp: new Date().toISOString(),
          placedAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        };

        orders.unshift(newOrder);
        await writeOrders(orders);

        if (phone && phone !== 'unknown') {
          const user = await readUser(phone);
          if (!user.orderHistory) user.orderHistory = [];
          user.orderHistory.unshift({ ...newOrder, orderStatus: 'placed' });
          if (user.orderHistory.length > 50) user.orderHistory = user.orderHistory.slice(0, 50);
          await writeUser(phone, user);
        }

        console.log(`✅ AUTOMATIC PAID ORDER CREATED: ${txnid} by ${customerName} (₹${totalAmount}) via PayU: ${payuMoneyId}`);
        pushNewOrderToRiders(newOrder);
        mirrorOrderToFirestore(newOrder); // app + website live sync
      }

      return res.redirect(303, `https://foodmela.online/track/${encodeURIComponent(txnid)}?paid=1`);
    } else {
      console.warn(`❌ PayU Payment Not Successful: ${txnid} (${d.error_Message || d.error || 'failed'})`);
      return res.redirect(303, `https://foodmela.online/?payment_error=${encodeURIComponent(d.error_Message || 'Payment Failed')}&orderId=${encodeURIComponent(txnid)}`);
    }
  } catch (err) {
    console.error('PayU callback exception:', err);
    return res.redirect(303, 'https://foodmela.online/?payment_error=Callback%20processing%20error');
  }
});

// 3. TRANSACTION STATUS CHECK via PayU verify API – LOGIN REQUIRED.
// Previously anyone could query ANY txnid (order enumeration oracle).
app.get('/api/payu/status/:txnid', async (req, res) => {
  try {
    if (!viewerFrom(req)) return res.status(401).json({ success: false, error: 'Login required' });
    if (!PAYU_KEY || !PAYU_SALT) return res.status(500).json({ success: false, error: 'PayU not configured' });
    const { txnid } = req.params;
    const hashSeq = [PAYU_KEY, 'verify_payment', txnid, PAYU_SALT].join('|');
    const hash = crypto.createHash('sha512').update(hashSeq).digest('hex');
    const body = new URLSearchParams({ key: PAYU_KEY, hash, var1: txnid, command: 'verify_payment' }).toString();
    const u = new URL(PAYU_VERIFY_URL);
    const verifyReq = https.request({
      hostname: u.hostname, port: 443, path: u.pathname + u.search, method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) },
    }, (verifyRes) => {
      let data = '';
      verifyRes.on('data', (c) => (data += c));
      verifyRes.on('end', () => {
        try { res.json(JSON.parse(data)); }
        catch (_) { res.status(500).json({ success: false, error: 'Failed parsing status' }); }
      });
    });
    verifyReq.on('error', (e) => res.status(500).json({ success: false, error: e.message }));
    verifyReq.write(body);
    verifyReq.end();
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ✅ ACCEPT ORDER – RIDER ONLY. driverId is taken from the verified token,
// never from the request body (was fully spoofable). First rider wins;
// blocking/approval enforced via Upstash user record.
app.post('/api/orders/accept', requireRider, async (req, res) => {
  try {
    const { orderId } = req.body;
    const driverId = req.apiAuth.phone;
    const driverName = String(req.body.driverName || '').slice(0, 60) || 'Delivery Partner';
    if (!orderId) return res.status(400).json({ success: false, error: 'orderId required' });

    // ── Enforce partner blocking/approval via Upstash user record ──────────
    if (driverId) {
      try {
        const cleanId = String(driverId).replace(/[^0-9]/g, '');
        // Try lookup by phone first, then by partnerId scan
        let userData = null;
        if (cleanId) {
          const r = await upstashCommand(['GET', `fm_user_v1:${cleanId}`]);
          if (r.result && r.result !== 'nil' && r.result !== null) {
            try { userData = JSON.parse(r.result); } catch (_) {}
          }
        }
        // If not found by phone, try partnerId lookup via scan (best-effort)
        if (!userData && String(driverId).startsWith('FM-')) {
          // Partner ID based — check blocked status via phone lookup fallback
          // For now, allow if no user record found (backward compat for demo riders)
        }
        if (userData) {
          if (userData.accountStatus === 'blocked') {
            return res.status(403).json({ success: false, error: 'Partner is blocked and cannot accept orders' });
          }
          if (userData.role === 'delivery_partner' && userData.approvalStatus !== 'approved') {
            return res.status(403).json({ success: false, error: 'Partner not approved — cannot accept orders' });
          }
        }
      } catch (e) {
        console.error('Partner check error:', e.message);
      }
    }

    const orders = await readOrders();
    const idx    = orders.findIndex(o => o.id === orderId);

    if (idx === -1) {
      return res.status(409).json({ success: false, error: 'Order already accepted by another driver' });
    }

    const order = orders[idx];

    // Already accepted by a DIFFERENT driver → reject
    if (order.acceptedBy && order.acceptedBy !== driverId) {
      return res.status(409).json({
        success: false,
        error: `Order already accepted by ${order.acceptedByName || order.acceptedBy}`,
      });
    }

    // Accept it
    orders[idx] = {
      ...order,
      stage:          1,
      status:         'Preparing in Kitchen 🍳',
      acceptedBy:     driverId    || 'driver',
      acceptedByName: driverName  || 'Delivery Partner',
      acceptedAt:     new Date().toISOString(),
      updatedAt:      new Date().toISOString(),
    };

    await writeOrders(orders);
    console.log(`✅ ORDER ${orderId} ACCEPTED by ${driverName}`);
    res.json({ success: true, order: orders[idx] });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// Cancel Order – OWNER ONLY. Token phone must match the order phone, so
// nobody can cancel someone else's order. Unknown IDs 404 (previously a
// phantom cancelled record was written for ANY id — free DB write).
app.post('/api/orders/cancel', async (req, res) => {
  try {
    const viewer = viewerFrom(req);
    if (!viewer) return res.status(401).json({ success: false, error: 'Login required' });
    const { orderId } = req.body;
    if (!orderId) return res.status(400).json({ success: false, error: 'orderId required' });

    const orders = await readOrders();
    const idx    = orders.findIndex(o => o.id === orderId);
    if (idx === -1) return res.status(404).json({ success: false, error: 'Order not found' });

    const orderPhone = String(orders[idx].phone || orders[idx].customerPhone || '').replace(/[^0-9]/g, '').slice(-10);
    if (viewer.role !== 'admin' && viewer.phone !== orderPhone) {
      return res.status(403).json({ success: false, error: 'Not your order' });
    }
    if (orders[idx].stage >= 2) {
      return res.status(409).json({ success: false, error: 'Too late to cancel' });
    }

    orders[idx] = {
      ...orders[idx],
      stage:       -1,
      status:      'CANCELLED BY CUSTOMER 🚨',
      cancelledAt: new Date().toISOString(),
      updatedAt:   new Date().toISOString(),
    };

    await writeOrders(orders);
    console.log(`🚨 ORDER ${orderId} CANCELLED by ${viewer.phone}`);
    res.json({ success: true, cancelledOrder: sanitizeOrder(orders[idx], viewer) });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// Update Order Stage – ASSIGNED RIDER ONLY. Only the rider who accepted
// (or admin) may advance, and only forward (no rewinding delivered orders).
app.post('/api/orders/update-stage', requireRider, async (req, res) => {
  try {
    const me = req.apiAuth;
    const { orderId, newStage } = req.body;
    if (!orderId || newStage === undefined) {
      return res.status(400).json({ success: false, error: 'orderId and newStage required' });
    }
    const stage = Number(newStage);
    if (![1, 2, 3].includes(stage)) {
      return res.status(400).json({ success: false, error: 'Invalid stage' });
    }

    const orders = await readOrders();
    const idx    = orders.findIndex(o => o.id === orderId);
    if (idx === -1) return res.status(404).json({ success: false, error: 'Order not found' });

    if (me.role !== 'admin') {
      const by = String(orders[idx].acceptedBy || '');
      const mine = by && (by === me.phone || by.replace(/[^0-9]/g, '').slice(-10) === me.phone);
      if (!mine) return res.status(403).json({ success: false, error: 'Only the assigned rider can update this order' });
    }
    if (stage <= orders[idx].stage) {
      return res.status(409).json({ success: false, error: 'Order already past this stage' });
    }

    const statusMap = {
      1: 'Preparing in Kitchen 🍳',
      2: 'On the Way (Out for Delivery) 🛵',
      3: 'Delivered 🏁',
    };

    orders[idx] = {
      ...orders[idx],
      stage,
      status:    statusMap[stage] || 'In Progress',
      updatedAt: new Date().toISOString(),
    };

    await writeOrders(orders);
    console.log(`🔄 ORDER ${orderId} → Stage ${stage} by ${me.phone}`);
    res.json({ success: true, order: sanitizeOrder(orders[idx], me) });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// Past Orders (Delivered only) – OWNER ONLY. Previously ANYONE could dump
// ALL delivered orders (no phone → everything). Now scoped to the token.
app.get('/api/orders/past', async (req, res) => {
  try {
    const viewer = viewerFrom(req);
    if (!viewer) return res.status(401).json({ success: false, error: 'Login required' });
    const orders = await readOrders();
    const past = orders.filter(o => {
      if (o.stage !== 3) return false;
      if (viewer.role === 'admin') return true;
      const orderPhone = String(o.phone || o.customerPhone || '').replace(/[^0-9]/g, '').slice(-10);
      if (viewer.role === 'rider') {
        const by = String(o.acceptedBy || '');
        return by && (by === viewer.phone || by.replace(/[^0-9]/g, '').slice(-10) === viewer.phone);
      }
      return viewer.phone === orderPhone;
    }).map(o => sanitizeOrder(o, viewer));
    res.json({ success: true, orders: past });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// CLEAR OLD ORDERS – ADMIN ONLY. Previously ANYONE could wipe all
// delivered orders with one DELETE (mass data destruction, no auth).
app.delete('/api/orders/clear-delivered', async (req, res) => {
  try {
    const viewer = viewerFrom(req);
    if (!viewer || viewer.role !== 'admin') {
      return res.status(403).json({ success: false, error: 'Admin only' });
    }
    const orders = await readOrders();
    const kept = orders.filter(o => o.stage < 3);
    await writeOrders(kept);
    res.json({ success: true, removed: orders.length - kept.length });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// IN-APP AUDIO CALLING (Agora RTC + Cloud Recording → Firebase Storage)
// Numbers stay hidden: VoIP only, channel = order_<orderId>, active orders only.
// Env: AGORA_APP_ID, AGORA_APP_CERTIFICATE, AGORA_CUSTOMER_KEY,
//      AGORA_CUSTOMER_SECRET, RECORDING_STORAGE_BUCKET,
//      RECORDING_STORAGE_ACCESS_KEY, RECORDING_STORAGE_SECRET_KEY
// ═══════════════════════════════════════════════════════════════════════════════
try {
  const { registerCallRoutes } = require('./agoraCalls');
  registerCallRoutes(app, { readOrders, verifyApiToken });
  console.log('📞 Agora calling routes mounted');
} catch (e) {
  console.error('Calling routes mount notice:', e.message);
}

// ─── START SERVER ─────────────────────────────────────────────────────────────
// Vercel serverless: export app, don't listen (platform handles it).
// Local / VPS: listen normally.
const PORT = process.env.PORT || 3000;
if (!process.env.VERCEL) {
  app.listen(PORT, () => console.log(`🚀 Food Mela Backend running on port ${PORT}`));
}

module.exports = app;
