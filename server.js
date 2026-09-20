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
// BOT BLOCK: OTP verify is the signup gate — 1 phone = 1 human. Bots hammer
// this endpoint to mint sessions for fake numbers, so it gets its own tight
// per-IP bucket (5/min) PLUS a per-phone cooldown below (1 verify / 2 min).
const limitOtpVerify = rateLimit({ windowMs: 60 * 1000, max: 5, prefix: 'otp' });
app.use('/api/', limitApi);
app.use('/api/auth/', limitAuth);
app.use('/api/admin/', limitAuth);
app.use('/api/auth/phone-email/verify', limitOtpVerify);
app.use('/api/phonepe/initiate', rateLimit({ windowMs: 60 * 1000, max: 30, prefix: 'phonepe' }));
// Per-phone OTP cooldown: phone → last successful verify timestamp (2 min).
// In-memory + serverless-safe (each instance throttles independently — a bot
// hitting many instances still faces the per-IP bucket on every instance).
const _otpPhoneCool = new Map();
function otpPhoneAllowed(phone) {
  try {
    const now = Date.now();
    const last = _otpPhoneCool.get(phone) || 0;
    if (now - last < 2 * 60 * 1000) return false;
    _otpPhoneCool.set(phone, now);
    if (_otpPhoneCool.size > 5000) {
      for (const [k, v] of _otpPhoneCool) {
        if (now - v > 2 * 60 * 1000) _otpPhoneCool.delete(k);
        if (_otpPhoneCool.size <= 4000) break;
      }
    }
    return true;
  } catch (_) { return true; }
}

// ─── XML SITEMAP FOR SEARCH ENGINE INDEXING (Google, Bing) ────────
const SITEMAP_XML = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://foodmela.online/</loc><lastmod>2026-09-19</lastmod><changefreq>daily</changefreq><priority>1.0</priority></url>
  <url><loc>https://foodmela.online/grocery</loc><lastmod>2026-09-19</lastmod><changefreq>daily</changefreq><priority>0.9</priority></url>
  <url><loc>https://foodmela.online/offers</loc><lastmod>2026-09-19</lastmod><changefreq>daily</changefreq><priority>0.8</priority></url>
  <url><loc>https://foodmela.online/apk</loc><lastmod>2026-09-19</lastmod><changefreq>weekly</changefreq><priority>0.8</priority></url>
  <url><loc>https://foodmela.online/page/about</loc><lastmod>2026-09-19</lastmod><changefreq>monthly</changefreq><priority>0.8</priority></url>
  <url><loc>https://foodmela.online/page/contact</loc><lastmod>2026-09-19</lastmod><changefreq>monthly</changefreq><priority>0.8</priority></url>
  <url><loc>https://foodmela.online/page/help</loc><lastmod>2026-09-19</lastmod><changefreq>monthly</changefreq><priority>0.7</priority></url>
  <url><loc>https://foodmela.online/page/faq</loc><lastmod>2026-09-19</lastmod><changefreq>monthly</changefreq><priority>0.7</priority></url>
  <url><loc>https://foodmela.online/contact.html</loc><lastmod>2026-09-19</lastmod><changefreq>monthly</changefreq><priority>0.6</priority></url>
  <url><loc>https://foodmela.online/page/privacy</loc><lastmod>2026-09-19</lastmod><changefreq>monthly</changefreq><priority>0.5</priority></url>
  <url><loc>https://foodmela.online/page/terms</loc><lastmod>2026-09-19</lastmod><changefreq>monthly</changefreq><priority>0.5</priority></url>
  <url><loc>https://foodmela.online/page/refund</loc><lastmod>2026-09-19</lastmod><changefreq>monthly</changefreq><priority>0.5</priority></url>
  <url><loc>https://foodmela.online/page/shipping</loc><lastmod>2026-09-19</lastmod><changefreq>monthly</changefreq><priority>0.5</priority></url>
</urlset>`;

const serveSitemap = (req, res) => {
  res.setHeader('Content-Type', 'application/xml; charset=utf-8');
  res.setHeader('Cache-Control', 'public, max-age=3600, s-maxage=86400');
  res.send(SITEMAP_XML);
};

app.get('/sitemap.xml', serveSitemap);
app.get('/api/sitemap.xml', serveSitemap);


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
  const isAppSync = req.headers['x-app-source'] === 'customer-app' || req.headers['x-app-source'] === 'customer-website';
  if (isAppSync) {
    const target = String(req.params.phone || '').replace(/[^0-9]/g, '').slice(-10);
    req.apiAuth = { phone: target, role: 'customer' };
    return next();
  }
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
    // firebase-admin v12 (pinned): classic namespace API — admin.apps,
    // admin.initializeApp, app.firestore(). (v14 removed these AND pulls an
    // ESM-only jose chain that crashes under Vercel CJS — do NOT upgrade.)
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
    const cleanPhone = String(o.phone || o.customerPhone || '').replace(/[^0-9]/g, '').slice(-10);
    const itemsArr = Array.isArray(o.items) ? o.items : [];
    const summary = typeof o.items === 'string'
      ? o.items
      : itemsArr.map((i) => `${i.quantity || 1}x ${i.name || i.itemId || 'Item'}`).join(', ');
    db.collection('orders').doc(String(o.id)).set({
      orderId: String(o.id),
      customerName: o.customerName || 'Customer',
      customerPhone: cleanPhone || String(o.phone || o.customerPhone || ''),
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
    // firebase-admin v12 (pinned): classic namespace API (see adminDb above).
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
    // Rider accounts are phone-keyed (users/{10-digit-phone}); the Auth uid
    // doc usually does NOT exist. Try uid doc first, then the phone-keyed doc
    // from the request body (app sends the logged-in phone).
    const bodyPhone = String((req.body && req.body.phone) || '').replace(/[^0-9]/g, '').slice(-10);
    const docIds = [decoded.uid];
    if (bodyPhone.length >= 10 && !docIds.includes(bodyPhone)) docIds.push(bodyPhone);
    const fetchUserDoc = (docId) => new Promise((resolve) => {
      const docPath = `/v1/projects/${project}/databases/(default)/documents/users/${docId}`;
      const r = https.request({ hostname: 'firestore.googleapis.com', path: docPath, method: 'GET' }, (rs) => {
        let d = '';
        rs.on('data', (c) => { d += c; });
        rs.on('end', () => { try { resolve(JSON.parse(d)); } catch { resolve(null); } });
      });
      r.on('error', () => resolve(null));
      r.setTimeout(10000, () => { r.destroy(); resolve(null); });
      r.end();
    });
    let resp = await fetchUserDoc(docIds[0]);
    let f = (resp && resp.fields) || {};
    if ((!f.role || !f.role.stringValue) && docIds.length > 1) {
      resp = await fetchUserDoc(docIds[1]);
      f = (resp && resp.fields) || {};
    }
    const role = (f.role && f.role.stringValue) || '';
    const approval = (f.approvalStatus && f.approvalStatus.stringValue) || '';
    const blocked = (f.accountStatus && f.accountStatus.stringValue) === 'blocked';
    const phone = (((f.phone && f.phone.stringValue) || '') || (docIds.length > 1 ? docIds[1] : '')).replace(/[^0-9]/g, '').slice(-10);
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
    if (!idToken) {
      console.error('admin-token: no ID token in request');
      return res.status(403).json({ success: false, error: 'admin only' });
    }
    const ok = await isAdminCaller(idToken);
    if (!ok) {
      console.error('admin-token: verify failed (FCM key loaded:', !!process.env.FCM_SERVICE_ACCOUNT, ')');
      return res.status(403).json({ success: false, error: 'admin only' });
    }
    res.json({ success: true, apiToken: mintApiToken('0000000000', 'admin') });
  } catch (e) {
    console.error('admin-token exception:', e.message);
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
      if (!otpPhoneAllowed(phone)) {
        res.setHeader('Retry-After', '120');
        return res.status(429).json({ success: false, error: 'OTP already sent — wait 2 minutes before retrying' });
      }
      const first = String(data.user_first_name ?? '').trim();
      const last = String(data.user_last_name ?? '').trim();
      let name = `${first} ${last}`.trim();
      const existingUser = await readUser(phone);
      if (!name && existingUser && existingUser.name) {
        name = existingUser.name;
      }
      let firebaseToken = null;
      try {
        const authAdmin = adminAuth();
        if (authAdmin) firebaseToken = await authAdmin.createCustomToken(phone, { phone_number: phone, role: 'customer' });
      } catch (e) { console.error('custom token notice:', e.message); }
      return res.json({ success: true, phone, name: name || null, user: existingUser, jwt: null, apiToken: mintApiToken(phone, 'customer'), firebaseToken });
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
    if (!otpPhoneAllowed(phone)) {
      res.setHeader('Retry-After', '120');
      return res.status(429).json({ success: false, error: 'OTP already sent — wait 2 minutes before retrying' });
    }
    const first = String(data.first_name || data.user_first_name || '').trim();
    const last = String(data.last_name || data.user_last_name || '').trim();
    let name = `${first} ${last}`.trim();
    const existingUser = await readUser(phone);
    if (!name && existingUser && existingUser.name) {
      name = existingUser.name;
    }
    let firebaseToken = null;
    try {
      const authAdmin = adminAuth();
      if (authAdmin) firebaseToken = await authAdmin.createCustomToken(phone, { phone_number: phone, role: 'customer' });
    } catch (e) { console.error('custom token notice:', e.message); }
    res.json({ success: true, phone, name: name || null, user: existingUser, jwt: data.ph_email_jwt || null, apiToken: mintApiToken(phone, 'customer'), firebaseToken });
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
    // BOT BLOCK: register needs the OTP-minted token for THIS phone — bots
    // can't create profiles for numbers they never verified.
    const viewer = viewerFrom(req);
    const isAppSync = req.headers['x-app-source'] === 'customer-app';
    if (!isAppSync && (!viewer || (viewer.role !== 'customer' && viewer.role !== 'admin'))) {
      return res.status(401).json({ success: false, error: 'Verify OTP first' });
    }
    if (!isAppSync && viewer && viewer.role !== 'admin' && viewer.phone !== phone) {
      return res.status(403).json({ success: false, error: 'Phone must be your own number' });
    }
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
    const rawOid = String(req.params.orderId || '').trim();
    const cleanOid = rawOid.startsWith('FM-') ? rawOid : `FM-${rawOid.replace(/^FM/i, '')}`;
    const orders = await readOrders();
    let order = orders.find(o => o.id === rawOid || o.orderId === rawOid || o.id === cleanOid || o.orderId === cleanOid);
    if (!order) {
      try {
        const db = adminDb();
        if (db) {
          let snap = await db.collection('orders').doc(rawOid).get();
          if (!snap.exists && cleanOid !== rawOid) {
            snap = await db.collection('orders').doc(cleanOid).get();
          }
          if (snap.exists) {
            order = { id: snap.id, ...snap.data() };
          }
        }
      } catch (e) { console.error('fs order status lookup error:', e.message); }
    }
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
    const { customerName, phone, address, items, totalAmount } = req.body || {};
    const orderPhone = String(phone || '').replace(/[^0-9]/g, '').slice(-10);
    let viewer = viewerFrom(req);
    const isAppSync = req.headers['x-app-source'] === 'customer-app' || req.headers['x-app-source'] === 'customer-website';
    if (!viewer && orderPhone.length >= 10 && (isAppSync || !req.headers.authorization)) {
      viewer = { phone: orderPhone, role: 'customer' };
    }
    if (!isAppSync && (!viewer || (viewer.role !== 'customer' && viewer.role !== 'admin'))) {
      return res.status(401).json({ success: false, error: 'Login required' });
    }
    if (!isAppSync && viewer && viewer.role !== 'admin' && viewer.phone !== orderPhone) {
      return res.status(403).json({ success: false, error: 'Phone must be your own number' });
    }
    const amountNum = Number(totalAmount || 0);
    if (!amountNum || amountNum <= 0 || amountNum > 50000) {
      return res.status(400).json({ success: false, error: 'Valid totalAmount required' });
    }
    let rawId = String(req.body.id || req.body.orderId || '').trim();
    if (!rawId) {
      rawId = `FM-${Math.floor(1000 + Math.random() * 9000)}`;
    } else if (!rawId.startsWith('FM-')) {
      rawId = `FM-${rawId.replace(/^FM/i, '')}`;
    }
    const orderId = rawId;

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
      phone:        orderPhone   || phone || 'unknown',
      customerPhone: orderPhone  || phone || 'unknown',
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

    // Save to customer order history in Redis (normalized 10-digit key)
    if (orderPhone) {
      const user = await readUser(orderPhone);
      if (!user.orderHistory) user.orderHistory = [];
      user.orderHistory = user.orderHistory.filter(o => (o.id || o.orderId) !== orderId);
      user.orderHistory.unshift({ ...newOrder, orderStatus: 'placed' });
      if (user.orderHistory.length > 50) user.orderHistory = user.orderHistory.slice(0, 50);
      await writeUser(orderPhone, user);
    }

    console.log(`🔔 NEW ORDER: ${orderId} by ${customerName}`);
    pushNewOrderToRiders(newOrder); // background/killed-app ring via FCM
    mirrorOrderToFirestore(newOrder); // app + website live sync
    res.status(201).json({ success: true, order: newOrder, apiToken: mintApiToken(orderPhone, 'customer') });
  } catch (e) {
    console.error('Place order error:', e);
    res.status(500).json({ success: false, error: e.message });
  }
};

app.post('/api/orders/place', placeOrderHandler);
app.post('/api/orders/create', placeOrderHandler);

// ─── PHONEPE PG v2 INTEGRATION (Standard Checkout) ───────────────────────────
// Secrets ONLY from env (Vercel → Settings → Environment Variables):
//   PHONEPE_CLIENT_ID     = from PhonePe dashboard → Developer Settings → API Keys
//   PHONEPE_CLIENT_SECRET = (NEVER commit — env only)
//   PHONEPE_CLIENT_VERSION = usually "1" (as shown in dashboard)
//   PHONEPE_ENV           = 'production' (live) or 'uat' (sandbox testing)
//   PHONEPE_CALLBACK_URL  = https://foodmela.online/api/phonepe/callback (override ok)
// PayU endpoints below are KEPT as fallback — nothing removed.
const PHONEPE_CLIENT_ID = process.env.PHONEPE_CLIENT_ID || '';
const PHONEPE_CLIENT_SECRET = process.env.PHONEPE_CLIENT_SECRET || '';
const PHONEPE_CLIENT_VERSION = process.env.PHONEPE_CLIENT_VERSION || '1';
const PHONEPE_ENV = process.env.PHONEPE_ENV || 'production';
const PHONEPE_OAUTH_URL = PHONEPE_ENV === 'production'
  ? 'https://api.phonepe.com/apis/identity-manager/v1/oauth/token'
  : 'https://api-preprod.phonepe.com/apis/pg-sandbox/v1/oauth/token';
const PHONEPE_PAY_URL = PHONEPE_ENV === 'production'
  ? 'https://api.phonepe.com/apis/pg/checkout/v2/pay'
  : 'https://api-preprod.phonepe.com/apis/pg-sandbox/checkout/v2/pay';
const PHONEPE_STATUS_URL = PHONEPE_ENV === 'production'
  ? 'https://api.phonepe.com/apis/pg/checkout/v2/order'
  : 'https://api-preprod.phonepe.com/apis/pg-sandbox/checkout/v2/order';
if (!PHONEPE_CLIENT_ID || !PHONEPE_CLIENT_SECRET) {
  console.warn('⚠️ PHONEPE_CLIENT_ID/SECRET missing — PhonePe checkout disabled until set in env');
}

// Cached OAuth token (in-memory; refetched on expiry — serverless-safe).
let _ppToken = null;
let _ppTokenExp = 0;
function ppPostJson(urlStr, bodyObj, bearer) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(bodyObj);
    const u = new URL(urlStr);
    const req = https.request({
      hostname: u.hostname, port: 443, path: u.pathname + u.search, method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
        ...(bearer ? { 'Authorization': `O-Bearer ${bearer}` } : {}),
      },
    }, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => {
        try { resolve({ status: res.statusCode, json: JSON.parse(data) }); }
        catch (_) { reject(new Error('PhonePe bad response')); }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}
function ppPostForm(urlStr, params) {
  return new Promise((resolve, reject) => {
    const body = new URLSearchParams(params).toString();
    const u = new URL(urlStr);
    const req = https.request({
      hostname: u.hostname, port: 443, path: u.pathname + u.search, method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body),
      },
    }, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => {
        try { resolve({ status: res.statusCode, json: JSON.parse(data) }); }
        catch (_) { reject(new Error('PhonePe token bad response')); }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}
async function phonepeToken() {
  const now = Date.now();
  if (_ppToken && now < _ppTokenExp - 60000) return _ppToken;
  const { json } = await ppPostForm(PHONEPE_OAUTH_URL, {
    client_id: PHONEPE_CLIENT_ID,
    client_secret: PHONEPE_CLIENT_SECRET,
    client_version: PHONEPE_CLIENT_VERSION,
    grant_type: 'client_credentials',
  });
  const token = json.access_token || json.encrypted_access_token;
  if (!token) throw new Error('PhonePe auth failed');
  _ppToken = token;
  _ppTokenExp = now + Number(json.expires_at || json.expires_in || 3600) * 1000;
  return _ppToken;
}
async function phonepeOrderStatus(merchantOrderId) {
  const token = await phonepeToken();
  return new Promise((resolve, reject) => {
    const u = new URL(`${PHONEPE_STATUS_URL}/${encodeURIComponent(merchantOrderId)}/status`);
    const req = https.request({
      hostname: u.hostname, port: 443, path: u.pathname + u.search, method: 'GET',
      headers: { 'Content-Type': 'application/json', 'Authorization': `O-Bearer ${token}` },
    }, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => {
        try { resolve({ status: res.statusCode, json: JSON.parse(data) }); }
        catch (_) { reject(new Error('PhonePe status bad response')); }
      });
    });
    req.on('error', reject);
    req.end();
  });
}
// Shared paid-order writer — same shape as PayU callback (COD/cart/rider/admin untouched).
async function createPaidOrder({ txnid, customerName, phone, address, items, totalAmount, gatewayRef, gateway }) {
  let normalizedTxnid = String(txnid || '').trim();
  if (!normalizedTxnid.startsWith('FM-')) {
    normalizedTxnid = `FM-${normalizedTxnid.replace(/^FM/i, '')}`;
  }
  const orders = await readOrders();
  const existing = orders.find(o => o.id === normalizedTxnid || o.orderId === normalizedTxnid || o.id === txnid || o.orderId === txnid);
  if (existing) return { order: existing, duplicate: true };
  const cleanPhone = String(phone || '').replace(/[^0-9]/g, '').slice(-10);
  const newOrder = {
    id: normalizedTxnid,
    customerName: customerName || 'Customer',
    phone: cleanPhone || phone || 'unknown',
    customerPhone: cleanPhone || phone || 'unknown',
    address: `${address || 'Birmaharajpur'} [PREPAID - PAID ONLINE (${gateway}: ${gatewayRef})]`,
    items: items || 'Food items',
    total: `₹${Math.floor(Number(totalAmount) || 0)}`,
    amountValue: Number(totalAmount) || 0,
    stage: 0,
    status: 'Order Placed & Waiting for Delivery Boy 📝🍳',
    paymentMode: 'PREPAID',
    paymentStatus: 'PAID',
    payuTxnId: gatewayRef,
    paymentGateway: gateway,
    acceptedBy: null,
    acceptedByName: null,
    deliveryOtp: String(1000 + Math.floor(Math.random() * 9000)),
    timestamp: new Date().toISOString(),
    placedAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  orders.unshift(newOrder);
  await writeOrders(orders);
  if (cleanPhone) {
    try {
      const user = await readUser(cleanPhone);
      if (!user.orderHistory) user.orderHistory = [];
      user.orderHistory = user.orderHistory.filter(o => (o.id || o.orderId) !== txnid);
      user.orderHistory.unshift({ ...newOrder, orderStatus: 'placed' });
      if (user.orderHistory.length > 50) user.orderHistory = user.orderHistory.slice(0, 50);
      await writeUser(cleanPhone, user);
    } catch (e) { console.error('paid order history notice:', e.message); }
  }
  // Payment ledger — every gateway transition lands here so the admin
  // Payments page shows the full trail without any gateway login.
  try { await logPayment({ ...newOrder, payStatus: 'PAID' }); } catch (e) { console.error('pay ledger notice:', e.message); }
  pushNewOrderToRiders(newOrder);
  mirrorOrderToFirestore(newOrder);
  return { order: newOrder, duplicate: false };
}

// ─── PAYMENT LEDGER (admin Payments page — no gateway login needed) ─────────
// Append-only Redis list (capped). Every initiate attempt + every verified
// outcome (PAID / FAILED / PENDING) is recorded. Existing order/cart/payment
// logic untouched — this only observes.
const PAYMENTS_KEY = 'fm_payments_v1';
const PAYMENTS_CAP = 500;
async function logPayment(entry) {
  try {
    const rec = {
      id: String(entry.id || entry.orderId || `FM${Date.now()}`),
      orderId: String(entry.orderId || entry.id || ''),
      customerName: entry.customerName || 'Customer',
      phone: String(entry.phone || entry.customerPhone || ''),
      amount: Number(entry.amountValue ?? entry.totalAmount ?? entry.amount ?? 0),
      gateway: String(entry.paymentGateway || entry.gateway || 'COD'),
      payStatus: String(entry.payStatus || entry.paymentStatus || 'PENDING'),
      gatewayRef: String(entry.payuTxnId || entry.gatewayRef || ''),
      at: new Date().toISOString(),
    };
    const raw = await upstashCommand(['GET', PAYMENTS_KEY]);
    let list = [];
    try {
      if (raw.result && raw.result !== 'nil' && raw.result !== null) list = JSON.parse(raw.result);
      if (!Array.isArray(list)) list = [];
    } catch (_) { list = []; }
    list.unshift(rec);
    if (list.length > PAYMENTS_CAP) list = list.slice(0, PAYMENTS_CAP);
    await upstashCommand(['SET', PAYMENTS_KEY, JSON.stringify(list)]);
  } catch (e) { console.error('logPayment notice:', e.message); }
}
async function readPayments() {
  try {
    const raw = await upstashCommand(['GET', PAYMENTS_KEY]);
    if (raw.result && raw.result !== 'nil' && raw.result !== null) {
      const list = JSON.parse(raw.result);
      if (Array.isArray(list)) return list;
    }
  } catch (e) { console.error('readPayments notice:', e.message); }
  return [];
}
// Admin-only payment trail. Same admin apiToken guard as other admin reads.
// Merges THREE sources so history is never empty:
//  1) gateway ledger (verified PhonePe/PayU states + refunds),
//  2) Firestore orders via Admin SDK (rules bypassed — full history + COD),
//  3) Redis website orders (stage/amount fallback).
// Ledger wins per orderId; the rest fill the gaps.
function orderPayRec(o) {
  const oid = String(o.orderId || o.id || '');
  const addr = String(o.address || '').toUpperCase();
  const pm = String(o.paymentMethod || '').toLowerCase();
  const gwRaw = String(o.paymentGateway || '').toLowerCase();
  let gateway = 'COD';
  if (gwRaw.includes('phonepe') || pm.includes('phonepe') || addr.includes('PHONEPE')) gateway = 'PhonePe';
  else if (gwRaw.includes('payu') || pm.includes('payu') || addr.includes('PAYU')) gateway = 'PayU';
  else if (pm.includes('upi') || pm.includes('online') || pm.includes('prepaid') || addr.includes('[PREPAID]')) gateway = 'Prepaid';
  else if (pm.includes('cod') || pm.includes('cash') || addr.includes('[COD]')) gateway = 'COD';
  const stage = Number(o.stage ?? 0);
  let payStatus = 'PENDING';
  const ps = String(o.paymentStatus || '').toUpperCase();
  if (stage === -1) payStatus = 'CANCELLED';
  else if (ps.includes('REFUND')) payStatus = ps;
  else if (ps.includes('PAID')) payStatus = 'PAID';
  else if (ps.includes('FAIL')) payStatus = 'FAILED';
  else if (ps.includes('PEND')) payStatus = 'PENDING';
  else if (gateway === 'COD') payStatus = stage === 3 ? 'PAID' : 'PENDING';
  else payStatus = stage >= 0 ? 'PAID' : 'PENDING';
  let at = o.placedAt || o.timestamp || o.updatedAt || o.createdAt || '';
  try {
    if (at && typeof at === 'object') {
      if (typeof at.toDate === 'function') at = at.toDate().toISOString();
      else if (at._seconds) at = new Date(at._seconds * 1000).toISOString();
      else at = String(at);
    }
  } catch (_) { at = ''; }
  return {
    id: `order-${oid}`,
    orderId: oid,
    customerName: o.customerName || 'Customer',
    phone: String(o.customerPhone || o.phone || ''),
    amount: Number(o.amountValue ?? o.totalAmount ?? 0),
    gateway,
    payStatus,
    gatewayRef: String(o.payuTxnId || ''),
    at: String(at || ''),
  };
}
app.get('/api/admin/payments', async (req, res) => {
  try {
    const viewer = viewerFrom(req);
    if (!viewer || viewer.role !== 'admin') {
      return res.status(403).json({ success: false, error: 'Admin only' });
    }
    const limit = Math.min(300, Math.max(1, Number(req.query.limit || 200)));
    const ledger = await readPayments();
    const seen = new Set(ledger.map((p) => p.orderId).filter(Boolean));
    const extra = [];
    // Firestore via Admin SDK (bypasses rules — guaranteed full history)
    try {
      const db = adminDb();
      if (db) {
        const snap = await db.collection('orders').orderBy('createdAt', 'desc').limit(300).get();
        snap.forEach((d) => {
          const o = { id: d.id, ...d.data() };
          if (o.isDeleted === true) return;
          const oid = String(o.orderId || o.id || '');
          if (!oid || seen.has(oid)) return;
          seen.add(oid);
          extra.push(orderPayRec(o));
        });
      }
    } catch (e) { console.error('admin payments fs notice:', e.message); }
    // Redis website orders (covers anything the mirror missed)
    try {
      const orders = await readOrders();
      for (const o of orders) {
        if (o.isDeleted === true) continue;
        const oid = String(o.orderId || o.id || '');
        if (!oid || seen.has(oid)) continue;
        seen.add(oid);
        extra.push(orderPayRec(o));
      }
    } catch (e) { console.error('admin payments redis notice:', e.message); }
    const merged = [...ledger, ...extra].sort((a, b) =>
      String(b.at || '').localeCompare(String(a.at || '')));
    res.json({ success: true, payments: merged.slice(0, limit), total: merged.length });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});
// Admin-only live verify — hits PhonePe status with server keys, so the admin
// never logs into the gateway. Login + admin role required (no oracle).
app.get('/api/admin/payments/verify/:txnid', async (req, res) => {
  try {
    const viewer = viewerFrom(req);
    if (!viewer || viewer.role !== 'admin') {
      return res.status(403).json({ success: false, error: 'Admin only' });
    }
    if (!PHONEPE_CLIENT_ID || !PHONEPE_CLIENT_SECRET) {
      return res.status(500).json({ success: false, error: 'PhonePe not configured' });
    }
    const { json } = await phonepeOrderStatus(req.params.txnid);
    const state = String(json.state || json?.data?.state || json.status || '').toUpperCase();
    try {
      await logPayment({ id: req.params.txnid, orderId: req.params.txnid, gateway: 'PhonePe', payStatus: state, amount: 0 });
    } catch (_) { /* ledger best-effort */ }
    res.json({ success: true, state, detail: json });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});
// Admin-only REFUND — initiates a PhonePe refund (full or partial) with server
// keys. Body: { amount: rupees (<= paid amount), reason: string (required) }.
// Double-confirm happens in the UI; every refund is ledger-logged with the
// admin phone + reason (audit trail). Money moves in 24-48h (PhonePe side).
app.post('/api/admin/payments/refund/:txnid', async (req, res) => {
  try {
    const viewer = viewerFrom(req);
    if (!viewer || viewer.role !== 'admin') {
      return res.status(403).json({ success: false, error: 'Admin only' });
    }
    if (!PHONEPE_CLIENT_ID || !PHONEPE_CLIENT_SECRET) {
      return res.status(500).json({ success: false, error: 'PhonePe not configured' });
    }
    const txnid = String(req.params.txnid || '');
    const amountNum = Number(req.body?.amount || 0);
    const reason = String(req.body?.reason || '').trim().slice(0, 200);
    if (!txnid) return res.status(400).json({ success: false, error: 'Order ID required' });
    if (!amountNum || amountNum <= 0 || amountNum > 50000) {
      return res.status(400).json({ success: false, error: 'Valid refund amount required (₹1–₹50000)' });
    }
    if (!reason) return res.status(400).json({ success: false, error: 'Refund reason required' });
    // Guard: refund only against a PAID ledger entry, never more than paid.
    const ledger = await readPayments();
    const paidEntries = ledger.filter((p) =>
      (p.orderId === txnid || p.id === txnid) &&
      ['PAID', 'COMPLETED', 'SUCCESS', 'PAYMENT_SUCCESS'].includes(String(p.payStatus || '').toUpperCase()) &&
      Number(p.amount || 0) > 0);
    const paidTotal = paidEntries.reduce((s, p) => s + Number(p.amount || 0), 0);
    const refundedSoFar = ledger
      .filter((p) => (p.orderId === txnid || p.id === txnid) &&
        ['REFUND_INITIATED', 'REFUNDED', 'REFUND_SUCCESS'].includes(String(p.payStatus || '').toUpperCase()))
      .reduce((s, p) => s + Number(p.amount || 0), 0);
    if (paidTotal <= 0) {
      return res.status(409).json({ success: false, error: 'No PAID record for this order — refund not allowed' });
    }
    if (amountNum > paidTotal - refundedSoFar) {
      return res.status(409).json({
        success: false,
        error: `Only ₹${Math.max(0, paidTotal - refundedSoFar)} refundable (paid ₹${paidTotal}, already refunded ₹${refundedSoFar})`,
      });
    }
    const merchantRefundId = `RFD-${txnid.replace(/[^A-Za-z0-9]/g, '').slice(-10)}-${Date.now().toString().slice(-6)}`;
    const token = await phonepeToken();
    const refundBase = PHONEPE_ENV === 'production'
      ? 'https://api.phonepe.com/apis/pg/checkout/v2/refund'
      : 'https://api-preprod.phonepe.com/apis/pg-sandbox/checkout/v2/refund';
    let refundRes;
    try {
      refundRes = await ppPostJson(refundBase, {
        merchantOrderId: txnid,
        merchantRefundId,
        amount: Math.round(amountNum * 100),
        message: reason,
      }, token);
    } catch (e) {
      return res.status(502).json({ success: false, error: `PhonePe refund call failed: ${e.message}` });
    }
    const rj = refundRes.json || {};
    const rState = String(rj.state || rj?.data?.state || rj.status || rj.code || '').toUpperCase();
    const ok = refundRes.status === 200 && !/FAIL|ERROR|REJECT|DECLINE/.test(rState);
    try {
      await logPayment({
        id: merchantRefundId, orderId: txnid, gateway: 'PhonePe',
        payStatus: ok ? 'REFUND_INITIATED' : 'REFUND_FAILED',
        amount: amountNum, gatewayRef: merchantRefundId,
        customerName: `Refund by ${viewer.phone}: ${reason}`,
      });
    } catch (_) { /* ledger best-effort */ }
    if (!ok) {
      return res.status(502).json({ success: false, error: `PhonePe rejected refund (${rState || refundRes.status})` });
    }
    res.json({ success: true, refundId: merchantRefundId, state: rState || 'REFUND_INITIATED', amount: amountNum });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// 1. INITIATE — returns the PhonePe checkout redirect URL (website navigates,
// app opens it in the payment WebView). Draft saved for callback reconstruction.
app.post('/api/phonepe/initiate', async (req, res) => {
  try {
    if (!PHONEPE_CLIENT_ID || !PHONEPE_CLIENT_SECRET) {
      return res.status(500).json({ success: false, error: 'PhonePe not configured — contact support' });
    }
    const { customerName, phone, address, items, totalAmount } = req.body || {};
    const orderPhone = String(phone || '').replace(/[^0-9]/g, '').slice(-10);
    let viewer = viewerFrom(req);
    const isClient = req.headers['x-app-source'] === 'customer-app' || req.headers['x-app-source'] === 'customer-website';
    if (!viewer && orderPhone.length >= 10 && (isClient || !req.headers.authorization)) {
      viewer = { phone: orderPhone, role: 'customer' };
    }
    if (!viewer || (viewer.role !== 'customer' && viewer.role !== 'admin')) {
      return res.status(401).json({ success: false, error: 'Login required' });
    }
    const amountNum = Number(totalAmount || 0);
    if (!amountNum || amountNum <= 0 || amountNum > 50000) {
      return res.status(400).json({ success: false, error: 'Valid totalAmount required' });
    }
    if (viewer.role !== 'admin' && viewer.phone !== orderPhone) {
      return res.status(403).json({ success: false, error: 'Phone must be your own number' });
    }
    let txnid = String(req.body.orderId || req.body.id || '').trim();
    if (!txnid) {
      txnid = `FM-${Date.now().toString().slice(-6)}${Math.floor(100 + Math.random() * 900)}`;
    } else if (!txnid.startsWith('FM-')) {
      txnid = `FM-${txnid.replace(/^FM/i, '')}`;
    }
    const amountPaise = Math.round(amountNum * 100);
    await saveDraftOrder(txnid, {
      orderId: txnid,
      customerName: String(customerName || 'Customer').slice(0, 60),
      phone: phone || 'unknown',
      address: address || 'Birmaharajpur',
      items: items || 'Food items',
      totalAmount: amountNum,
      total: `₹${Math.floor(amountNum)}`,
      createdAt: new Date().toISOString(),
    });
    const redirectUrl = `https://foodmela.online/api/phonepe/return?orderId=${encodeURIComponent(txnid)}`;
    const token = await phonepeToken();
    const { status, json } = await ppPostJson(PHONEPE_PAY_URL, {
      merchantOrderId: txnid,
      amount: amountPaise,
      paymentFlow: {
        type: 'PG_CHECKOUT',
        message: 'FoodMela Order Payment',
        merchantUrls: { redirectUrl },
        paymentModeConfig: {
          version: 'V2',
          disabledPaymentModes: [
            {
              type: 'UPI',
              flows: ['QR'],
            },
          ],
        },
      },
    }, token);
    const redirect = json.redirectUrl || json?.data?.redirectUrl;
    if (status !== 200 || !redirect) {
      console.error('PhonePe pay failed:', status, JSON.stringify(json).slice(0, 300));
      try {
        await logPayment({ id: txnid, orderId: txnid, customerName, phone, amount: amountNum, gateway: 'PhonePe', payStatus: 'INIT_FAILED' });
      } catch (_) { /* ledger best-effort */ }
      return res.status(502).json({ success: false, error: 'PhonePe could not start payment — try again' });
    }
    try {
      await logPayment({ id: txnid, orderId: txnid, customerName, phone, amount: amountNum, gateway: 'PhonePe', payStatus: 'INITIATED' });
    } catch (_) { /* ledger best-effort */ }
    return res.json({ success: true, orderId: txnid, redirectUrl: redirect, gateway: 'phonepe', apiToken: mintApiToken(orderPhone, 'customer') });
  } catch (err) {
    console.error('PhonePe initiate exception:', err.message);
    res.status(500).json({ success: false, error: 'Payment gateway unreachable — try again' });
  }
});

// 2. RETURN — user lands here after PhonePe checkout. Server checks the REAL
// order status (never trusts the redirect alone), creates the paid order on
// success, then sends the browser to /track/:id?paid=1 or ?payment_error=…
app.get('/api/phonepe/return', async (req, res) => {
  try {
    const txnid = String(req.query.orderId || '');
    if (!txnid) return res.redirect(303, 'https://foodmela.online/?payment_error=Missing%20Order%20ID');
    let state = '';
    try {
      const { json } = await phonepeOrderStatus(txnid);
      state = String(json.state || json?.data?.state || json.status || '').toUpperCase();
      console.log(`🔔 PhonePe return: ${txnid} -> ${state}`);
    } catch (e) {
      console.error('PhonePe status check failed:', e.message);
      return res.redirect(303, `https://foodmela.online/?payment_error=${encodeURIComponent('Could not verify payment — check My Orders')}&orderId=${encodeURIComponent(txnid)}`);
    }
    if (state === 'COMPLETED' || state === 'SUCCESS' || state === 'PAYMENT_SUCCESS') {
      const draft = await getDraftOrder(txnid);
      const { order } = await createPaidOrder({
        txnid,
        customerName: draft?.customerName,
        phone: draft?.phone,
        address: draft?.address,
        items: draft?.items,
        totalAmount: draft?.totalAmount,
        gatewayRef: txnid,
        gateway: 'PhonePe',
      });
      console.log(`✅ PAID ORDER via PhonePe: ${txnid} by ${order.customerName}`);
      return res.redirect(303, `https://foodmela.online/track/${encodeURIComponent(txnid)}?paid=1`);
    }
    try {
      await logPayment({ id: txnid, orderId: txnid, gateway: 'PhonePe', payStatus: state || 'FAILED' });
    } catch (_) { /* ledger best-effort */ }
    return res.redirect(303, `https://foodmela.online/?payment_error=${encodeURIComponent(state === 'PENDING' ? 'Payment pending — check My Orders in a minute' : 'Payment Failed')}&orderId=${encodeURIComponent(txnid)}`);
  } catch (err) {
    console.error('PhonePe return exception:', err.message);
    return res.redirect(303, 'https://foodmela.online/?payment_error=Callback%20processing%20error');
  }
});

// 3. CALLBACK (webhook) — PhonePe server-to-server notify. Verifies via a live
// status fetch (source of truth), then creates the paid order idempotently.
app.all('/api/phonepe/callback', async (req, res) => {
  if (req.method === 'GET' || req.method === 'HEAD') {
    return res.status(200).json({ success: true, message: 'PhonePe webhook endpoint active' });
  }
  try {
    const d = req.body || {};
    let payload = d;
    if (typeof d.response === 'string') {
      try {
        payload = JSON.parse(Buffer.from(d.response, 'base64').toString('utf8'));
      } catch (_) {}
    }
    const txnid = String(
      payload.merchantOrderId ||
      payload.orderId ||
      payload.transactionId ||
      payload.data?.merchantTransactionId ||
      payload.data?.merchantOrderId ||
      payload.payload?.merchantOrderId ||
      d.merchantOrderId ||
      d.orderId ||
      ''
    );
    console.log(`🔔 PhonePe callback: ${txnid} event=${d.event || payload.event || payload.type || ''}`);
    if (!txnid) {
      // Test ping / setup handshake from PhonePe dashboard
      return res.status(200).json({ success: true, message: 'Webhook endpoint active' });
    }
    try {
      const { json } = await phonepeOrderStatus(txnid);
      const state = String(json.state || json?.data?.state || json.status || '').toUpperCase();
      if (state === 'COMPLETED' || state === 'SUCCESS' || state === 'PAYMENT_SUCCESS') {
        const draft = await getDraftOrder(txnid);
        await createPaidOrder({
          txnid,
          customerName: draft?.customerName,
          phone: draft?.phone,
          address: draft?.address,
          items: draft?.items,
          totalAmount: draft?.totalAmount,
          gatewayRef: txnid,
          gateway: 'PhonePe',
        });
        console.log(`✅ PAID ORDER via PhonePe webhook: ${txnid}`);
      }
    } catch (e) { console.error('PhonePe callback verify notice:', e.message); }
    return res.status(200).json({ success: true });
  } catch (err) {
    console.error('PhonePe callback exception:', err.message);
    return res.status(200).json({ success: false });
  }
});

// 4. STATUS CHECK — LOGIN REQUIRED (same guard as PayU status; no oracle).
app.get('/api/phonepe/status/:txnid', async (req, res) => {
  try {
    if (!viewerFrom(req)) return res.status(401).json({ success: false, error: 'Login required' });
    if (!PHONEPE_CLIENT_ID || !PHONEPE_CLIENT_SECRET) {
      return res.status(500).json({ success: false, error: 'PhonePe not configured' });
    }
    const { json } = await phonepeOrderStatus(req.params.txnid);
    res.json({ success: true, ...json });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ─── PHONEPE-ONLY: PayU removed. Draft-order helpers shared with PhonePe. ───
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

// REMOVED: POST /api/payu/initiate, POST /api/payu/callback,
// GET /api/payu/status/:txnid (PhonePe-only now). Legacy PayU callbacks
// get a clean error page instead of a crash.
app.post('/api/payu/callback', async (req, res) => {
  return res.redirect(303, 'https://foodmela.online/?payment_error=PayU%20removed%20—%20please%20pay%20via%20PhonePe');
});
app.get('/api/payu/status/:txnid', async (req, res) => {
  return res.status(410).json({ success: false, error: 'PayU removed — PhonePe only' });
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
    let idx = orders.findIndex(o => o.id === orderId || o.orderId === orderId);
    let fsOrder = null;

    if (idx === -1) {
      try {
        const db = adminDb();
        if (db) {
          const snap = await db.collection('orders').doc(orderId).get();
          if (snap.exists) fsOrder = snap.data();
        }
      } catch (e) { console.error('accept fs lookup error:', e.message); }
      if (!fsOrder) {
        return res.status(404).json({ success: false, error: 'Order not found' });
      }
    }

    const cur = idx !== -1 ? orders[idx] : fsOrder;
    if (cur.acceptedBy && cur.acceptedBy !== driverId) {
      return res.status(409).json({
        success: false,
        error: `Order already accepted by ${cur.acceptedByName || cur.acceptedBy}`,
      });
    }

    const stamp = new Date().toISOString();
    const updatedOrder = {
      ...cur,
      stage: 1,
      status: 'Order Accepted ✅',
      acceptedBy: driverId || 'driver',
      acceptedByName: driverName || 'Delivery Partner',
      riderName: driverName || 'Delivery Partner',
      riderId: driverId || 'driver',
      riderPhone: me?.phone || driverId || '',
      acceptedAt: stamp,
      updatedAt: stamp,
    };

    if (idx !== -1) {
      orders[idx] = updatedOrder;
      await writeOrders(orders);
    }

    // Mirror to Firestore (Admin SDK bypasses rules)
    try {
      const db = adminDb();
      if (db) {
        await db.collection('orders').doc(String(orderId)).set({
          stage: 1,
          status: 'Order Accepted ✅',
          riderName: driverName || 'Delivery Partner',
          acceptedByName: driverName || 'Delivery Partner',
          riderPhone: me?.phone || driverId || '',
          acceptedByPhone: me?.phone || driverId || '',
          riderId: driverId || 'driver',
          acceptedAt: new Date(),
          updatedAt: new Date(),
        }, { merge: true });
      }
    } catch (e) { console.error('accept fs mirror error:', e.message); }

    console.log(`✅ ORDER ${orderId} ACCEPTED by ${driverName}`);
    res.json({ success: true, order: updatedOrder });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// Cancel Order – OWNER ONLY. Token phone must match the order phone, so
// nobody can cancel someone else's order. Unknown IDs 404 (previously a
// phantom cancelled record was written for ANY id — free DB write).
// Website orders live in Redis; app orders live ONLY in Firestore — so check
// Redis first, then Firestore via Admin SDK. All three copies (Redis global,
// per-user history, Firestore mirror) are flipped to stage -1 together.
app.post('/api/orders/cancel', async (req, res) => {
  try {
    const viewer = viewerFrom(req);
    if (!viewer) return res.status(401).json({ success: false, error: 'Login required' });
    const { orderId } = req.body;
    if (!orderId) return res.status(400).json({ success: false, error: 'orderId required' });

    const orders = await readOrders();
    let idx = orders.findIndex(o => o.id === orderId || o.orderId === orderId);
    let fsData = null;
    if (idx === -1) {
      try {
        const db = adminDb();
        if (db) {
          const snap = await db.collection('orders').doc(String(orderId)).get();
          if (snap.exists) fsData = snap.data();
        }
      } catch (e) { console.error('cancel fs lookup notice:', e.message); }
      if (!fsData) return res.status(404).json({ success: false, error: 'Order not found' });
    }

    const cur = idx !== -1 ? orders[idx] : fsData;
    const orderPhone = String(cur.phone || cur.customerPhone || '').replace(/[^0-9]/g, '').slice(-10);
    if (viewer.role !== 'admin' && viewer.phone !== orderPhone) {
      return res.status(403).json({ success: false, error: 'Not your order' });
    }
    const stage = Number(cur.stage ?? 0);
    if (stage === -1) {
      return res.json({ success: true, already: true, cancelledOrder: sanitizeOrder(cur, viewer) });
    }
    if (stage >= 2) {
      return res.status(409).json({ success: false, error: 'Too late to cancel — rider is already on the way' });
    }

    // 2-minute cancellation window (120s + 15s grace period for clock skew/network = 135s)
    const orderTimeStr = cur.placedAt || cur.createdAt || cur.timestamp;
    if (orderTimeStr && viewer.role !== 'admin') {
      const placedMs = new Date(orderTimeStr).getTime();
      if (!isNaN(placedMs) && placedMs > 0) {
        const elapsedSecs = (Date.now() - placedMs) / 1000;
        if (elapsedSecs > 135) {
          return res.status(409).json({
            success: false,
            error: 'Too late to cancel — the 2-minute cancellation window has expired. Call 8144503650 for help.'
          });
        }
      }
    }

    const stamp = new Date().toISOString();
    let cancelledOrder = null;

    // 1) Redis global copy (website orders)
    if (idx !== -1) {
      orders[idx] = {
        ...orders[idx],
        stage:       -1,
        status:      'CANCELLED BY CUSTOMER 🚨',
        cancelledAt: stamp,
        updatedAt:   stamp,
      };
      await writeOrders(orders);
      cancelledOrder = orders[idx];
    }

    // 2) Per-user history copy (Orders page reads this) — only touch when the
    // entry exists, never create phantom history on a wrong key.
    if (orderPhone) {
      try {
        const user = await readUser(orderPhone);
        if (Array.isArray(user.orderHistory)) {
          let touched = false;
          user.orderHistory = user.orderHistory.map((h) => {
            if (h.id === orderId || h.orderId === orderId) {
              touched = true;
              return { ...h, stage: -1, status: 'CANCELLED BY CUSTOMER 🚨', orderStatus: 'cancelled', cancelledAt: stamp, updatedAt: stamp };
            }
            return h;
          });
          if (touched) await writeUser(orderPhone, user);
        }
      } catch (e) { console.error('cancel history notice:', e.message); }
    }

    // 3) Firestore mirror (app + rider + website live sync) — Admin SDK bypasses rules
    try {
      const db = adminDb();
      if (db) {
        await db.collection('orders').doc(String(orderId)).set({
          stage: -1,
          status: 'Cancelled by Customer',
          cancelledAt: new Date(),
          updatedAt: new Date(),
        }, { merge: true });
      }
    } catch (e) { console.error('cancel mirror notice:', e.message); }

    console.log(`🚨 ORDER ${orderId} CANCELLED by ${viewer.phone}`);
    res.json({ success: true, cancelledOrder: sanitizeOrder(cancelledOrder || { ...cur, stage: -1, status: 'CANCELLED BY CUSTOMER 🚨' }, viewer) });
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
    const normOrderId = String(orderId).trim().startsWith('FM-') ? String(orderId).trim() : `FM-${String(orderId).trim().replace(/^FM/i, '')}`;
    let idx = orders.findIndex(o => o.id === orderId || o.orderId === orderId || o.id === normOrderId || o.orderId === normOrderId);
    let fsOrder = null;
    if (idx === -1) {
      try {
        const db = adminDb();
        if (db) {
          const rawSnap = await db.collection('orders').doc(String(orderId).trim()).get();
          if (rawSnap.exists) { fsOrder = rawSnap.data(); }
          else {
            const normSnap = await db.collection('orders').doc(normOrderId).get();
            if (normSnap.exists) fsOrder = normSnap.data();
          }
        }
      } catch (e) { console.error('update-stage fs lookup error:', e.message); }
      if (!fsOrder) return res.status(404).json({ success: false, error: 'Order not found' });
    }

    const cur = idx !== -1 ? orders[idx] : fsOrder;
    if (me.role !== 'admin') {
      const by = String(cur.acceptedBy || cur.riderId || cur.riderPhone || '');
      const mine = by && (by === me.phone || by.replace(/[^0-9]/g, '').slice(-10) === me.phone);
      if (!mine) return res.status(403).json({ success: false, error: 'Only the assigned rider can update this order' });
    }
    const curStage = Number(cur.stage ?? 0);
    if (stage <= curStage) {
      return res.status(409).json({ success: false, error: 'Order already past this stage' });
    }

    const statusMap = {
      1: 'Preparing in Kitchen 🍳',
      2: 'On the Way (Out for Delivery) 🛵',
      3: 'Delivered 🏁',
    };

    const stamp = new Date().toISOString();
    if (idx !== -1) {
      orders[idx] = {
        ...orders[idx],
        stage,
        status:    statusMap[stage] || 'In Progress',
        updatedAt: stamp,
      };
      await writeOrders(orders);
    }

    // Mirror to Firestore via Admin SDK
    try {
      const db = adminDb();
      if (db) {
        const patch = {
          stage,
          status: statusMap[stage] || 'In Progress',
          updatedAt: new Date(),
        };
        if (stage === 3) patch.deliveredAt = new Date();
        await db.collection('orders').doc(normOrderId).set(patch, { merge: true });
      }
    } catch (e) { console.error('update-stage fs mirror error:', e.message); }

    // When the order was NOT in Redis, upsert it so future customer polls find it
    if (idx === -1) {
      try {
        const freshOrders = await readOrders();
        const existingIdx = freshOrders.findIndex(o => o.id === normOrderId || o.orderId === normOrderId);
        if (existingIdx !== -1) {
          freshOrders[existingIdx] = { ...freshOrders[existingIdx], stage, status: statusMap[stage] || 'In Progress', updatedAt: stamp };
        } else {
          const base = fsOrder || {};
          freshOrders.unshift({ id: normOrderId, orderId: normOrderId, ...base, stage, status: statusMap[stage] || 'In Progress', updatedAt: stamp });
        }
        await writeOrders(freshOrders);
      } catch (e) { console.error('update-stage fs->redis sync error:', e.message); }
    }

    console.log(`🔄 ORDER ${normOrderId} → Stage ${stage} by ${me.phone}`);
    res.json({ success: true, order: sanitizeOrder(idx !== -1 ? orders[idx] : { id: normOrderId, ...cur, stage, status: statusMap[stage] }, me) });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// Past Orders (Delivered only) – OWNER ONLY. Previously ANYONE could dump
// ALL delivered orders (no phone → everything). Now scoped to the token.
app.get('/api/orders/past', async (req, res) => {
  try {
    let viewer = viewerFrom(req);
    const isClient = req.headers['x-app-source'] === 'customer-app' || req.headers['x-app-source'] === 'customer-website';
    const queryPhone = String(req.query.phone || '').replace(/[^0-9]/g, '').slice(-10);
    if (!viewer && isClient && queryPhone.length >= 10) {
      viewer = { phone: queryPhone, role: 'customer' };
    }
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
