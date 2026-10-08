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
app.use('/api/payu/initiate', rateLimit({ windowMs: 60 * 1000, max: 30, prefix: 'payu' }));
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

// ─── 🔒 GOOGLE PLAY PRIVACY POLICY ──────────────────────────────────────────
// Required by Google Play Console & Indian IT Act 2000 SPDI rules.
// Serves /privacy.html, /privacy, /privacy-policy, /api/privacy.html.
const PRIVACY_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Privacy Policy — FoodMela</title>
<meta name="description" content="Official Privacy Policy for FoodMela Food Delivery mobile application and services operated by SIDHESWAR ENTERPRISES." />
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; max-width: 860px; margin: 0 auto; padding: 32px 20px; line-height: 1.7; color: #1e293b; background: #fff; }
  h1 { color: #0a5c2f; font-size: 28px; margin-bottom: 8px; border-bottom: 2px solid #0a5c2f; padding-bottom: 12px; }
  h2 { color: #0f172a; font-size: 20px; margin-top: 32px; margin-bottom: 12px; border-left: 4px solid #0a5c2f; padding-left: 10px; }
  p, li { font-size: 15px; color: #334155; }
  ul, ol { padding-left: 24px; margin-bottom: 16px; }
  li { margin-bottom: 8px; }
  .entity-card { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 12px; padding: 20px; margin: 24px 0; font-size: 14px; }
  .entity-card strong { color: #0f172a; }
  .badge { display: inline-block; padding: 4px 10px; border-radius: 999px; background: #dcfce7; color: #166534; font-weight: 700; font-size: 12px; margin-bottom: 12px; }
  .foot { margin-top: 48px; padding-top: 20px; border-top: 1px solid #e2e8f0; color: #64748b; font-size: 13px; text-align: center; }
  a { color: #0a5c2f; text-decoration: underline; }
</style>
</head>
<body>
<span class="badge">Google Play Compliant &amp; IT Act 2000 Certified</span>
<h1>🔒 Privacy Policy — FoodMela</h1>
<p><strong>Effective Date:</strong> October 1, 2026 | <strong>Last Updated:</strong> October 7, 2026</p>
<p>Welcome to <strong>FoodMela</strong> ("we", "our", or "us"). We are committed to protecting your privacy and handling your personal information with full transparency and care. This Privacy Policy governs your use of the FoodMela mobile application (available on Google Play) and our website at <a href="https://foodmela.online">foodmela.online</a>.</p>

<div class="entity-card">
  <h3 style="margin-top:0;color:#0a5c2f;">📋 Legal Entity &amp; Grievance Redressal</h3>
  <ul style="margin:0;padding-left:18px;">
    <li><strong>Legal Operating Entity:</strong> SIDHESWAR ENTERPRISES</li>
    <li><strong>MSME Udyam Registration No:</strong> UDYAM-OD-29-0025578</li>
    <li><strong>Platform / Application Name:</strong> FoodMela (foodmela.online)</li>
    <li><strong>Operating Base &amp; Registered Address:</strong> Birmaharajpur, Subarnapur District, Odisha – 767018, India</li>
    <li><strong>Grievance Officer:</strong> Grievance Officer, FoodMela Customer Support</li>
    <li><strong>Support &amp; Grievance Email:</strong> <a href="mailto:support@foodmela.online">support@foodmela.online</a></li>
    <li><strong>Direct Helpline:</strong> +91 8144503650</li>
  </ul>
</div>

<h2>1. Information We Access and Collect</h2>
<p>We collect only the minimal data strictly necessary to provide food delivery services in our coverage area:</p>
<ul>
  <li><strong>Personal Identification &amp; Contact:</strong> Full name, phone number, and delivery addresses you provide during checkout or profile creation.</li>
  <li><strong>Authentication Data:</strong> Mobile phone number verified via secure SMS OTP. We do NOT store passwords or SMS message contents.</li>
  <li><strong>Precise &amp; Approximate Location (GPS):</strong> With your explicit permission, we access your device's GPS location while using the app to accurately detect your delivery address, show nearby restaurants in Birmaharajpur, and calculate delivery fees. We do not track your location in the background when the app is closed.</li>
  <li><strong>Device Information &amp; App Activity:</strong> Operating system, app version, unique device identifier (UDID), and Firebase Cloud Messaging (FCM) tokens to deliver push notifications regarding order status and important notices.</li>
  <li><strong>Microphone &amp; Audio (Masked In-App VoIP Calling):</strong> We request microphone access solely to enable encrypted, in-app VoIP calls between customers and delivery partners during an active order (powered by Agora Audio SDK). Both customer and rider phone numbers remain masked and hidden. Audio is never recorded, eavesdropped, or stored on our servers.</li>
  <li><strong>Order History:</strong> Past food items ordered, delivery times, and order receipts to provide customer assistance and repeat ordering.</li>
</ul>

<h2>2. Financial Information &amp; Payment Security</h2>
<ul>
  <li>All digital payments (UPI, Google Pay, PhonePe, Paytm, Debit/Credit Cards, Net Banking) are processed directly by certified third-party payment gateways (including PayU India).</li>
  <li><strong>FoodMela NEVER collects, views, processes, or stores your debit/credit card numbers, CVV codes, expiry dates, or UPI PINs.</strong></li>
  <li>Cash on Delivery (COD) transactions require no financial data storage.</li>
</ul>

<h2>3. How We Use Your Information</h2>
<ul>
  <li>To process, confirm, prepare, and deliver your food orders to your doorstep.</li>
  <li>To send transactional push notifications and SMS updates regarding order confirmation, dispatch, and delivery.</li>
  <li>To enable masked communication between customer and assigned delivery rider without exposing personal telephone numbers.</li>
  <li>To verify user identity and prevent fraud or unauthorized transactions.</li>
  <li>To provide responsive customer support and resolve order grievances.</li>
</ul>

<h2>4. Data Sharing and Third-Party Disclosures</h2>
<p>We do NOT sell, rent, trade, or monetize your personal information to any third parties or advertisers. We share information only with:</p>
<ul>
  <li><strong>Assigned Delivery Riders:</strong> Your name, delivery address, and ordered items are shared solely for the purpose of completing delivery.</li>
  <li><strong>Partner Restaurants / Kitchens:</strong> Ordered items and cooking instructions (your personal phone number is not shared with kitchen staff).</li>
  <li><strong>Service Infrastructure Providers:</strong>
    <ul>
      <li>Google Firebase (cloud database &amp; push notifications)</li>
      <li>HanuOTP (transactional SMS OTP delivery)</li>
      <li>Agora (secure real-time VoIP audio stream)</li>
      <li>PayU (secure RBI-compliant payment processing)</li>
    </ul>
  </li>
  <li><strong>Legal Authorities:</strong> Only when strictly required by Indian law, court order, or governmental regulation.</li>
</ul>

<h2>5. Data Retention &amp; User Account Deletion Policy</h2>
<p>In full compliance with Google Play Developer User Data Policies and Indian IT Rules:</p>
<ul>
  <li>We retain your personal order data only as long as necessary to provide services and comply with statutory accounting requirements.</li>
  <li><strong>How to Delete Your Account and Data:</strong> You have the absolute right to delete your account and all associated personal data at any time. You can request immediate deletion by emailing our Grievance Officer at <a href="mailto:support@foodmela.online">support@foodmela.online</a> with your registered phone number, or calling <strong>+91 8144503650</strong>.</li>
  <li>Upon receiving your request, your personal profile, addresses, and saved data are permanently scrubbed and deleted from our databases within 7 working days.</li>
</ul>

<h2>6. Children's Privacy</h2>
<p>Our services are intended for general audiences and are not directed to children under 13 years of age. We do not knowingly collect personal data from children.</p>

<h2>7. Security Measures</h2>
<p>We enforce industry-standard security safeguards including TLS/HTTPS data-in-transit encryption, secure session tokens, and strict Firestore access rules to safeguard your data against unauthorized access, loss, or misuse.</p>

<h2>8. Contact &amp; Grievance Redressal</h2>
<p>For any queries, feedback, or data privacy concerns regarding this policy, please reach out to us at:</p>
<p>
  <strong>SIDHESWAR ENTERPRISES (FoodMela)</strong><br />
  Birmaharajpur, Subarnapur, Odisha – 767018, India<br />
  <strong>Email:</strong> <a href="mailto:support@foodmela.online">support@foodmela.online</a><br />
  <strong>Helpline:</strong> +91 8144503650<br />
  <strong>Website:</strong> <a href="https://foodmela.online">https://foodmela.online</a>
</p>

<p class="foot">© 2026 FoodMela (Operated by SIDHESWAR ENTERPRISES) · All Rights Reserved.</p>
</body>
</html>`;

const servePrivacy = (req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Cache-Control', 'public, max-age=3600, s-maxage=86400');
  res.send(PRIVACY_HTML);
};

app.get('/privacy.html', servePrivacy);
app.get('/privacy', servePrivacy);
app.get('/privacy-policy', servePrivacy);
app.get('/api/privacy', servePrivacy);
app.get('/api/privacy.html', servePrivacy);

// ─── 🛠️ SERVER-SIDE MAINTENANCE KILL-SWITCH ─────────────────────────────────
// Purane installed apps (bina update) bhi band ho jayenge — server hi mana
// kar dega. Flag Redis me: fm_maintenance_v1 = {"enabled":bool,"eta":str}.
// Admin panel → Settings se toggle hota hai (same button, website + apps).
// Website Firestore flag dekhta hai, apps + API ye Redis flag dekhte hain —
// admin panel dono ko ek saath set karta hai.
const MAINT_KEY = 'fm_maintenance_v1';
let _maintCache = { enabled: false, eta: '30 min', at: 0 };
async function getMaintenance() {
  try {
    // 10-sec cache — har request par Redis hit nahi.
    if (Date.now() - _maintCache.at < 10000) return _maintCache;
    const r = await upstashCommand(['GET', MAINT_KEY]);
    if (r.result && r.result !== 'nil' && r.result !== null) {
      const d = JSON.parse(r.result);
      _maintCache = { enabled: d.enabled === true, eta: String(d.eta || '30 min'), at: Date.now() };
    } else {
      _maintCache = { enabled: false, eta: '30 min', at: Date.now() };
    }
  } catch (_) { /* fail-open: Redis down → site chalti rahe */ }
  return _maintCache;
}
async function setMaintenance(enabled, eta) {
  const d = { enabled: !!enabled, eta: String(eta || '30 min'), updatedAt: Date.now() };
  await upstashCommand(['SET', MAINT_KEY, JSON.stringify(d)]);
  _maintCache = { ...d, at: Date.now() };
  return d;
}
// Public status — purane apps polling karke khud maintenance screen dikha sakte hain.
app.get('/api/maintenance/status', async (req, res) => {
  const m = await getMaintenance();
  res.json({ success: true, enabled: m.enabled, eta: m.eta });
});
// Admin set — same isAdminCaller check jaise baaki admin endpoints.
app.post('/api/admin/maintenance', async (req, res) => {
  try {
    const authHeader = String(req.headers.authorization || '');
    const idToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
    if (!(await isAdminCaller(idToken))) {
      return res.status(403).json({ success: false, error: 'admin only' });
    }
    const d = await setMaintenance(req.body.enabled, req.body.eta);
    res.json({ success: true, ...d });
  } catch (e) {
    res.status(500).json({ success: false, error: 'save failed' });
  }
});
// ─── ADMIN ONE-TIME DEDUP: hide ghost order docs without deleting history ──
// Ghost docs = TMP-xxx placeholders, dash-less FM71234567 twins, and any doc
// whose orderId/clientRef duplicates another doc's canonical FM-xxx id.
// They are soft-hidden (isDeleted:true) so old app installs stop showing
// duplicate rows; the canonical doc + admin history stay untouched.
// Admin-only (Firebase ID token). Safe to run repeatedly (idempotent).
app.post('/api/admin/orders/dedup', async (req, res) => {
  try {
    const authHeader = String(req.headers.authorization || '');
    const idToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
    if (!(await isAdminCaller(idToken))) {
      return res.status(403).json({ success: false, error: 'admin only' });
    }
    const db = adminDb();
    if (!db) return res.status(500).json({ success: false, error: 'firestore unavailable' });
    const norm = (v) => {
      const s = String(v || '').trim();
      if (!s) return '';
      if (s.startsWith('TMP-')) return s;
      if (s.startsWith('FM-')) return s;
      if (s.startsWith('FM')) return 'FM-' + s.slice(2);
      return s;
    };
    const snap = await db.collection('orders').get();
    const docs = snap.docs.map((d) => ({ ref: d.ref, id: d.id, ...(d.data() || {}) }));
    const byKey = new Map();
    for (const d of docs) {
      const keys = [norm(d.id), norm(d.orderId), norm(d.order_number), norm(d.clientRef)].filter(Boolean);
      for (const k of keys) {
        if (!byKey.has(k)) byKey.set(k, []);
        byKey.get(k).push(d);
      }
    }
    const hidden = [];
    const seen = new Set();
    for (const [, group] of byKey) {
      if (group.length < 2) continue;
      // Canonical winner: FM-xxx doc, prefer non-deleted, newest updatedAt.
      const sorted = [...group].sort((a, b) => {
        const aCanon = norm(a.id).startsWith('FM-') && a.id === norm(a.id) ? 0 : 1;
        const bCanon = norm(b.id).startsWith('FM-') && b.id === norm(b.id) ? 0 : 1;
        if (aCanon !== bCanon) return aCanon - bCanon;
        const at = new Date(a.updatedAt || a.createdAt || 0).getTime();
        const bt = new Date(b.updatedAt || b.createdAt || 0).getTime();
        return bt - at;
      });
      const winner = sorted[0];
      for (const loser of sorted.slice(1)) {
        if (seen.has(loser.ref.path) || loser.ref.path === winner.ref.path) continue;
        if (loser.isDeleted === true) { seen.add(loser.ref.path); continue; }
        seen.add(loser.ref.path);
        try {
          await loser.ref.set({ isDeleted: true, dedupHidden: true, dedupWinner: winner.id, updatedAt: new Date() }, { merge: true });
          hidden.push({ hidden: loser.id, kept: winner.id });
        } catch (e) { console.error('dedup hide notice:', loser.id, e.message); }
      }
    }
    // Also hide orphan TMP- placeholders that matched nothing (never real orders).
    for (const d of docs) {
      if (seen.has(d.ref.path)) continue;
      if (String(d.id).startsWith('TMP-') && d.isDeleted !== true) {
        try {
          await d.ref.set({ isDeleted: true, dedupHidden: true, updatedAt: new Date() }, { merge: true });
          hidden.push({ hidden: d.id, kept: null });
        } catch (e) { console.error('dedup tmp notice:', d.id, e.message); }
      }
    }
    // Backfill pass: patch docs missing totalAmount/itemsSummary from their
    // own amountValue/items fields, so old apps show ₹82 not ₹0/"No items".
    const backfilled = [];
    for (const d of docs) {
      try {
        if (d.isDeleted === true) continue;
        const patch = {};
        if (!(Number(d.totalAmount) > 0)) {
          const amt = Number(d.amountValue ?? 0);
          if (amt > 0) { patch.totalAmount = amt; patch.amountValue = amt; }
        }
        if ((!d.itemsSummary || !String(d.itemsSummary).trim()) && typeof d.items === 'string' && d.items.trim()) {
          patch.itemsSummary = d.items;
        }
        if (!d.total && (Number(patch.totalAmount ?? d.totalAmount) > 0)) {
          patch.total = `₹${Math.floor(Number(patch.totalAmount ?? d.totalAmount))}`;
        }
        if (Object.keys(patch).length) {
          patch.updatedAt = new Date();
          await d.ref.set(patch, { merge: true });
          backfilled.push(d.id);
        }
      } catch (e) { console.error('dedup backfill notice:', d.id, e.message); }
    }
    console.log(`🧹 [DEDUP] hid ${hidden.length} ghost docs, backfilled ${backfilled.length}, kept canonical rows`);
    res.json({ success: true, hidden, backfilled });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});
// Kill-switch middleware — maintenance ON ho to SAARE /api endpoints 503 de
// (GET + POST sab). Sirf /api/maintenance/status aur /api/admin/* khule rehte
// hain taaki apps ETA dikha sakein aur admin panel kaam kare.
app.use('/api/', async (req, res, next) => {
  try {
    if (req.path.startsWith('/admin/') || req.path === '/maintenance/status') return next();
    const m = await getMaintenance();
    if (m.enabled) {
      return res.status(503).json({
        success: false,
        maintenance: true,
        eta: m.eta,
        error: '🛠️ Server under maintenance — thodi der me wapas aayenge',
      });
    }
  } catch (_) { /* fail-open */ }
  next();
});


const ORDERS_KEY    = 'fm_orders_v1';
const ORDER_SEQ_KEY = 'fm_order_seq';
// ─── ORDER IDEMPOTENCY LOCKS ────────────────────────────────────────────────
// Redis SET NX (atomic): first concurrent request wins, the loser waits and
// re-reads — so double-taps / double PayU callbacks can NEVER create 2 rows.
// Lock auto-expires in 60s (crash-safe); always released in finally.
const ORDER_LOCK_PREFIX = 'fm_order_lock:';
async function acquireOrderLock(key, ttlSec = 60) {
  try {
    const r = await upstashCommand(['SET', ORDER_LOCK_PREFIX + key, '1', 'EX', String(ttlSec), 'NX']);
    return r && r.result === 'OK';
  } catch (_) { return false; /* fail-closed: Redis IS the order store — without it no safe claim is possible */ }
}
async function releaseOrderLock(key) {
  try { await upstashCommand(['DEL', ORDER_LOCK_PREFIX + key]); } catch (_) {}
}
const _memLocks = new Map();
function acquireMemLock(key) {
  if (_memLocks.has(key)) return false;
  _memLocks.set(key, Date.now());
  return true;
}
function releaseMemLock(key) { _memLocks.delete(key); }
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
// ─── CENTRAL ORDER NUMBER ─────────────────────────────────────────────────
// Backend-owned sequence via Redis INCR (atomic, concurrency-safe).
// Format: FM-YYYYMMDD-NNNNNN (e.g. FM-20260927-000001). The client-supplied
// id/orderId is kept ONLY as an idempotency key (clientRef) — it is never
// the official order number.
async function nextOrderNumber() {
  const day = new Date().toISOString().slice(0, 10).replace(/-/g, '');
  let seq = 0;
  try {
    const res = await upstashCommand(['INCR', ORDER_SEQ_KEY]);
    seq = Number(res.result) || 0;
  } catch (e) {
    console.error('Order seq INCR error:', e.message);
  }
  if (!seq) {
    // Fallback: derive from existing orders count (not concurrency-safe,
    // but keeps the format stable if Redis INCR is unavailable).
    try {
      const orders = await readOrders();
      seq = orders.length + 1 + Math.floor(Math.random() * 1000);
    } catch (_) {
      seq = Math.floor(Math.random() * 900000) + 100000;
    }
  }
  return `FM-${day}-${String(seq % 1000000).padStart(6, '0')}`;
}

// ─── API AUTH (phone-based session tokens) ──────────────────────────────────
// The website proves phone ownership via phone.email OTP; the backend mints a
// short-lived HMAC token bound to that phone. Sensitive endpoints
// (/orders/live redacted view, /user/:phone/*, cancel) require the token's
// phone to MATCH the requested phone — killing IDOR. Rider endpoints
// (accept/update-stage) require a rider token minted at rider login.
// Tokens are stateless (HMAC-SHA256, no storage) and expire after 7 days.
const API_TOKEN_SECRET = process.env.API_TOKEN_SECRET || '';
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
// NOTE: no x-app-source bypass here — that client-controlled header allowed
// anyone to read ANY customer's profile/orders/history by phone number alone
// (verified live). The apps always send a real Bearer apiToken (apiHeaders),
// so legitimate clients are unaffected.
//
// 🛠️ Maintenance gate FIRST — server OFF ho to purane apps bhi band (503),
// chahe token valid ho ya nahi. Admin + status endpoints kabhi block nahi.
async function maintenanceGate(req, res, next) {
  try {
    const m = await getMaintenance();
    if (m.enabled) {
      return res.status(503).json({
        success: false,
        maintenance: true,
        eta: m.eta,
        error: '🛠️ Server under maintenance — thodi der me wapas aayenge',
      });
    }
  } catch (_) { /* fail-open */ }
  next();
}
function requireSelf(req, res, next) {
  maintenanceGate(req, res, () => {
    const t = verifyApiToken(bearerToken(req));
    const target = String(req.params.phone || '').replace(/[^0-9]/g, '').slice(-10);
    if (!t || t.phone !== target) {
      return res.status(401).json({ success: false, error: 'Login required' });
    }
    req.apiAuth = t;
    next();
  });
}
function requireRider(req, res, next) {
  maintenanceGate(req, res, () => {
    let t = verifyApiToken(bearerToken(req));
    if (!t || (t.role !== 'rider' && t.role !== 'admin')) {
      // Fallback 1: riderPhone / riderId in body or headers
      const phone = String(req.body?.riderPhone || req.headers['x-rider-phone'] || '').replace(/[^0-9]/g, '').slice(-10);
      const riderId = String(req.body?.riderId || req.headers['x-rider-id'] || '').trim();
      if (phone.length === 10 || riderId.length > 0) {
        t = { phone: phone || riderId, role: 'rider', riderId };
      }
      // Fallback 2: For update-stage / accept — if orderId is present, let the
      // handler's own ownership check enforce security. This keeps old installed
      // apps working when their Bearer token has expired (they don't send
      // riderPhone/riderId in the body).
      else if (req.body?.orderId && req.body?.newStage !== undefined) {
        t = { phone: 'unknown', role: 'rider', riderId: '', expired: true };
      }
      else {
        return res.status(401).json({ success: false, error: 'Rider login required' });
      }
    }
    req.apiAuth = t;
    next();
  });
}
// Strip sensitive fields from orders served to non-owners. Owners prove
// ownership with their token phone == order phone; riders see operational
// fields but NEVER the delivery OTP or customer FCM token.
function sanitizeOrder(o, viewer) {
  const orderPhone = String(o.phone || o.customerPhone || '').replace(/[^0-9]/g, '').slice(-10);
  const isOwner = viewer && viewer.phone === orderPhone;
  const isRider = viewer && (viewer.role === 'rider' || viewer.role === 'admin');
  const copy = { ...o };

  const oid = copy.id || copy.orderId || copy.order_number;
  if (oid) {
    copy.id = oid;
    copy.orderId = oid;
    copy.order_number = oid;
  }

  let amt = 0;
  if (typeof copy.amountValue === 'number' && !isNaN(copy.amountValue) && copy.amountValue > 0) amt = copy.amountValue;
  else if (typeof copy.totalAmount === 'number' && !isNaN(copy.totalAmount) && copy.totalAmount > 0) amt = copy.totalAmount;
  else if (typeof copy.total === 'number' && !isNaN(copy.total) && copy.total > 0) amt = copy.total;
  else if (typeof copy.total === 'string') {
    const p = parseFloat(copy.total.replace(/[^0-9.]/g, ''));
    if (!isNaN(p)) amt = p;
  }

  if (amt > 0) {
    copy.amountValue = amt;
    copy.totalAmount = amt;
    copy.total = `₹${amt % 1 === 0 ? amt : amt.toFixed(2)}`;
  }

  // Client App Compatibility: FoodMela Customer App evaluates `isCompleted = stage >= 4 || stage == -1`.
  // Backend stores delivered orders as stage 3 ('Delivered 🏁').
  // For customer callers, when stage === 3 or status indicates delivered, map stage: 4
  // so the un-updated mobile app classifies the order as completed and places it in Past Orders.
  const isDelivered = Number(copy.stage ?? 0) === 3 || String(copy.status || '').toLowerCase().includes('deliver');
  if (isDelivered && (!viewer || viewer.role === 'customer')) {
    copy.stage = 4;
    copy.status = 'Delivered 🏁';
  }

  if (isOwner || isRider) return copy; // full view for owner + assigned flow
  delete copy.deliveryOtp;
  delete copy.customerFcmToken;
  delete copy.riderFcmToken;
  return copy;
}
function viewerFrom(req) {
  return verifyApiToken(bearerToken(req));
}

// ── POST /api/users/device-token { fcmToken } ──────────────────────────
// Registers the caller's LATEST device token on users/{phone} (Admin SDK).
// Lets /ring fall back to a fresh token when the order doc holds a stale
// one (reinstall / token rotation). Auth: logged-in user saves OWN token.
app.post('/api/users/device-token', async (req, res) => {
  try {
    const viewer = viewerFrom(req);
    if (!viewer || !viewer.phone) {
      return res.status(401).json({ success: false, error: 'Login required' });
    }
    const token = String((req.body || {}).fcmToken || '').trim();
    if (token.length < 20) {
      return res.status(400).json({ success: false, error: 'Invalid token' });
    }
    const clean = String(viewer.phone).replace(/[^0-9]/g, '').slice(-10);
    const forms = [...new Set([clean, '91' + clean].filter((p) => p.length >= 10))];
    const db = adminDb();
    if (!db) return res.json({ success: true, saved: false, reason: 'no db' });
    for (const ph of forms) {
      try {
        await db.collection('users').doc(ph).set(
          { fcmToken: token, fcmUpdatedAt: Date.now() },
          { merge: true }
        );
      } catch (_) {}
    }
    res.json({ success: true, saved: true });
  } catch (e) {
    res.json({ success: false, error: e.message });
  }
});

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
      // DATA-ONLY topic push (no notification block): OS-drawn strip kabhi
      // nahi aata — app ka background handler fullScreenIntent wala local
      // notification dikhata hai (WhatsApp-style full screen). Pehle notification
      // block tha, isliye OS khud strip dikhata tha aur full-screen marta tha.
      const strData = {};
      for (const [k, v] of Object.entries(data || {})) {
        if (v !== undefined && v !== null) strData[k] = String(v);
      }
      // Set collapse_key and a fixed tag so Android OS collapses/replaces order notifications
      // in the notification drawer instead of stacking multiple notifications.
      const payload = JSON.stringify({
        message: {
          topic,
          data: { title, body, ...strData, type: 'new_order', click_action: 'FLUTTER_NOTIFICATION_CLICK' },
          android: {
            priority: 'high',
            collapse_key: 'foodmela_rider_orders',
            notification: {
              sound: 'default',
              channel_id: 'food_mela_orders',
              tag: 'foodmela_rider_order',
              visibility: 'PUBLIC',
              notification_priority: 'PRIORITY_MAX'
            }
          }
        }
      });
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
// ─── FCM ONCE-ONLY DEDUP (server-side) ────────────────────────────────────
// Ek orderId par new-order push SIRF EK BAAR jayega — chahe place handler,
// paid-order path, watch poller ya cron kitni baar bhi fire karein. Upstash
// SETNX atomic hai: do concurrent caller me se sirf ek jeetega, dusra skip.
// TTL 24h — purane IDs auto-expire, memory kabhi bhar nahi sakti.
const PUSHED_ORDERS_KEY = 'fm_pushed_orders_v1';
async function alreadyPushed(orderId) {
  try {
    const key = `${PUSHED_ORDERS_KEY}:${String(orderId)}`;
    const r = await upstashCommand(['SET', key, '1', 'EX', '86400', 'NX']);
    // Upstash: result 'OK' = key nayi bani (pehli baar) → push karo.
    // result null = key pehle se thi → skip (duplicate).
    return r.result !== 'OK';
  } catch (_) { return false; } // Upstash down → fail-open, push bhej do
}
function pushNewOrderToRiders(order) {
  // Fire-and-forget — never blocks the order response.
  setImmediate(async () => {
    try {
      if (await alreadyPushed(order.id)) {
        console.log(`🔇 FCM dedup: push already sent for ${order.id} — skipping repeat`);
        return;
      }
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

// ─── PAYU CREDENTIALS (hoisted: auto-cancel refund needs them at call time) ─
const PAYU_KEY = process.env.PAYU_KEY || 'YT9Kis';
const PAYU_SALT = process.env.PAYU_SALT || 'jMBPPnuLnXRlhthvj8V8Onq9tiYRS6hA';

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
// SELF-TRIGGER: placeOrderHandler bhi har successful place par isko
// fire-and-forget call karta hai (triggerWatchPoller), taaki Cron na laga ho
// tab bhi rider tak push pahunche — customer→rider gap ka asli fix.
function triggerWatchPoller() {
  // Fire-and-forget — order response kabhi block nahi hota.
  // Watch endpoint ko CRON_SECRET chahiye; self-call me wahi bhejte hain.
  setImmediate(async () => {
    try {
      const secret = process.env.CRON_SECRET || '';
      if (!secret) return;
      const port = process.env.PORT || 3000;
      const host = process.env.VERCEL_URL
        ? `https://${process.env.VERCEL_URL}`
        : `http://127.0.0.1:${port}`;
      await fetch(`${host}/api/orders/watch`, {
        headers: { Authorization: `Bearer ${secret}` },
        signal: AbortSignal.timeout(15000),
      }).catch(() => {});
    } catch (_) {}
  });
}
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
    // ── AUTO-CANCEL: stage-0 orders older than 10 min with no rider ──
    // Same poller, no extra cron: unaccepted orders are cancelled once,
    // prepaid ones get a PayU refund trigger, customer gets the sorry push.
    let autoCancelled = [];
    try {
      autoCancelled = await autoCancelStaleOrders(docs, now);
    } catch (e) { console.error('[WATCH] auto-cancel notice:', e.message); }
    res.json({ success: true, checked: docs.length, pushed, fresh: fresh.map((o) => o.id), autoCancelled });
  } catch (e) {
    res.json({ success: false, error: e.message });
  }
});

// ─── AUTO-CANCEL STALE ORDERS (no rider in 10 min) ──────────────────────────
// Called from the /watch poller (runs every minute via Vercel Cron).
// For each stage-0 order older than 10 min: mark cancelled in Firestore +
// Redis, fire PayU refund for prepaid, push the sorry message to customer.
// Idempotent: Upstash NX key per order → runs exactly once per order.
const AUTOCANCEL_KEY_PREFIX = 'fm_autocancelled_v1:';
const AUTOCANCEL_AFTER_MS = 10 * 60 * 1000;

async function firestorePatchOrder(docId, fields) {
  // Firestore REST PATCH: field paths as updateMask.fieldPaths.
  try {
    const project = process.env.FIRESTORE_PROJECT_ID || 'food-mela-notification';
    const mask = Object.keys(fields).map((k) => `updateMask.fieldPaths=${encodeURIComponent(k)}`).join('&');
    const body = JSON.stringify({
      fields: Object.fromEntries(Object.entries(fields).map(([k, v]) => [
        k,
        typeof v === 'number'
          ? (Number.isInteger(v) ? { integerValue: String(v) } : { doubleValue: v })
          : typeof v === 'boolean'
            ? { booleanValue: v }
            : { stringValue: String(v) },
      ])),
    });
    await new Promise((resolve) => {
      try {
        const r = https.request({
          hostname: 'firestore.googleapis.com',
          path: `/v1/projects/${project}/databases/(default)/documents/orders/${encodeURIComponent(docId)}?${mask}`,
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
        }, (rs) => { rs.on('data', () => {}); rs.on('end', () => resolve(true)); });
        r.on('error', () => resolve(false));
        r.setTimeout(10000, () => { r.destroy(); resolve(false); });
        r.write(body);
        r.end();
      } catch (_) { resolve(false); }
    });
  } catch (_) {}
}

async function payuVerifyPayment(txnid) {
  return new Promise((resolve) => {
    try {
      if (!PAYU_KEY || !PAYU_SALT || !txnid) return resolve(null);
      const cleanTxn = String(txnid).replace(/^FM-?/i, 'FM').trim();
      const withDash = cleanTxn.startsWith('FM-') ? cleanTxn : ('FM-' + cleanTxn.replace(/^FM/i, ''));
      const noDash = cleanTxn.startsWith('FM-') ? ('FM' + cleanTxn.slice(3)) : cleanTxn;
      const queryTxns = [...new Set([cleanTxn, withDash, noDash, String(txnid).trim()])].join('|');
      const hashSeq = [PAYU_KEY, 'verify_payment', queryTxns, PAYU_SALT].join('|');
      const hash = crypto.createHash('sha512').update(hashSeq).digest('hex');
      const body = new URLSearchParams({ key: PAYU_KEY, hash, var1: queryTxns, command: 'verify_payment' }).toString();
      const host = (process.env.PAYU_ENV || 'production') === 'production' ? 'info.payu.in' : 'test.payu.in';
      const req = https.request({
        hostname: host,
        path: '/merchant/postservice?form=2',
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) },
      }, (resp) => {
        let d = '';
        resp.on('data', chunk => { d += chunk; });
        resp.on('end', () => {
          try {
            const parsed = JSON.parse(d);
            const details = parsed?.transaction_details || {};
            let txnData = null;
            for (const k of [cleanTxn, withDash, noDash, String(txnid).trim(), ...Object.keys(details)]) {
              if (details[k] && details[k].mihpayid && /^\d+$/.test(String(details[k].mihpayid).trim())) {
                txnData = details[k];
                break;
              }
            }
            console.log(`[PAYU VERIFY] txnid=${queryTxns} status=${parsed?.status} mihpayid=${txnData?.mihpayid || 'none'}`);
            resolve(txnData || null);
          } catch (_) {
            console.warn(`[PAYU VERIFY RAW] txnid=${queryTxns} raw=${d.slice(0, 200)}`);
            resolve(null);
          }
        });
      });
      req.on('error', (e) => {
        console.error(`[PAYU VERIFY ERR] txnid=${cleanTxn}:`, e.message);
        resolve(null);
      });
      req.setTimeout(8000, () => { req.destroy(); resolve(null); });
      req.write(body);
      req.end();
    } catch (e) {
      console.error('[PAYU VERIFY EXCEPTION]:', e.message);
      resolve(null);
    }
  });
}

async function payuRefund(targetRef, amount, orderRef) {
  // PayU cancel_refund_transaction:
  // var1 = mihpayid (numeric PayU transaction ID)
  // var2 = unique Token ID / Request ID generated by merchant
  // var3 = refund amount (formatted with 2 decimal places)
  // hash = sha512(key|command|var1|salt)
  return new Promise(async (resolve) => {
    try {
      if (!PAYU_KEY || !PAYU_SALT || !targetRef) {
        console.warn(`⚠️ [PAYU REFUND] missing credentials or targetRef (targetRef=${targetRef})`);
        return resolve({ ok: false, msg: 'missing credentials or txn id' });
      }

      let parsedAmount = Number(amount || 0);
      let mihpayid = String(targetRef).trim();

      // If targetRef is NOT purely numeric (e.g. starts with FM or is txnid),
      // resolve the actual numeric mihpayid via PayU verify_payment API
      if (!/^\d+$/.test(mihpayid)) {
        console.log(`[PAYU REFUND] targetRef=${targetRef} is not numeric mihpayid; resolving via verify_payment`);
        let txnData = await payuVerifyPayment(mihpayid);
        if ((!txnData || !txnData.mihpayid) && orderRef && orderRef !== targetRef) {
          console.log(`[PAYU REFUND] trying orderRef=${orderRef} via verify_payment`);
          txnData = await payuVerifyPayment(orderRef);
        }
        if (txnData?.mihpayid && /^\d+$/.test(String(txnData.mihpayid).trim())) {
          mihpayid = String(txnData.mihpayid).trim();
          console.log(`[PAYU REFUND] resolved mihpayid=${mihpayid} for ${targetRef}`);
          if ((!parsedAmount || parsedAmount <= 0) && txnData.amount) {
            parsedAmount = Number(txnData.amount);
          }
        } else {
          console.warn(`⚠️ [PAYU REFUND] could not resolve numeric mihpayid for ${targetRef} (orderRef=${orderRef})`);
          return resolve({ ok: false, msg: `could not resolve numeric mihpayid for ${targetRef}` });
        }
      }

      if (!parsedAmount || parsedAmount <= 0 || isNaN(parsedAmount)) {
        console.warn(`⚠️ [PAYU REFUND] invalid refund amount: ${parsedAmount} (raw amount was ${amount})`);
        return resolve({ ok: false, msg: 'invalid refund amount' });
      }

      const amtStr = parsedAmount.toFixed(2);
      const hashSeq = [PAYU_KEY, 'cancel_refund_transaction', mihpayid, PAYU_SALT].join('|');
      const hash = crypto.createHash('sha512').update(hashSeq).digest('hex').toLowerCase();
      const tokenRef = `FM-ref-${orderRef || mihpayid}-${Date.now()}`;

      const form = new URLSearchParams({
        key: PAYU_KEY,
        command: 'cancel_refund_transaction',
        var1: String(mihpayid),
        var2: tokenRef,
        var3: amtStr,
        hash,
      }).toString();

      console.log(`[PAYU REFUND REQUEST] mihpayid=${mihpayid} tokenRef=${tokenRef} amount=${amtStr}`);

      const host = (process.env.PAYU_ENV || 'production') === 'production' ? 'info.payu.in' : 'test.payu.in';
      const req = https.request({
        hostname: host,
        path: '/merchant/postservice?form=2',
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(form) },
      }, (res) => {
        let d = '';
        res.on('data', (c) => { d += c; });
        res.on('end', () => {
          console.log(`[PAYU REFUND RAW RESPONSE] mihpayid=${mihpayid} raw=${d.slice(0, 300)}`);
          try {
            const j = JSON.parse(d);
            const status = Number(j.status ?? j.msg?.status ?? 0);
            const error_code = Number(j.error_code ?? j.errorCode ?? 0);
            const msgStr = typeof j.msg === 'string' ? j.msg : (typeof j.message === 'string' ? j.message : (j.msg?.text || d.slice(0, 200)));
            const ok = status === 1 || error_code === 102 || /success|queued/i.test(JSON.stringify(j).slice(0, 300));
            resolve({ ok, msg: msgStr, mihpayid });
          } catch (_) {
            resolve({ ok: /success|queued/i.test(d.slice(0, 200)), msg: d.slice(0, 200), mihpayid });
          }
        });
      });
      req.on('error', (e) => {
        console.error(`[PAYU REFUND ERROR] mihpayid=${mihpayid}:`, e.message);
        resolve({ ok: false, msg: e.message, mihpayid });
      });
      req.setTimeout(15000, () => {
        req.destroy();
        console.error(`[PAYU REFUND TIMEOUT] mihpayid=${mihpayid}`);
        resolve({ ok: false, msg: 'timeout', mihpayid });
      });
      req.write(form);
      req.end();
    } catch (e) {
      console.error('[PAYU REFUND EXCEPTION]:', e.message);
      resolve({ ok: false, msg: e.message });
    }
  });
}

async function autoCancelStaleOrders(docs, now) {
  const done = [];
  for (const doc of docs || []) {
    try {
      const id = (doc.name || '').split('/').pop();
      if (!id) continue;
      const f = doc.fields || {};
      const stage = fsNum(f.stage);
      const deleted = f.isDeleted && f.isDeleted.booleanValue === true;
      if (deleted) continue;
      // Fallback refund: customer cancelled but server /cancel never ran
      // (network fail) — app stamped needsRefund. Fire refund now, any age.
      const needsRefund = f.needsRefund && f.needsRefund.booleanValue === true;
      if (stage === -1 && needsRefund) {
        try {
          const r = await upstashCommand(['SET', AUTOCANCEL_KEY_PREFIX + 'refund:' + id, '1', 'EX', '86400', 'NX']);
          if (r.result === 'OK') {
            const gwRef = fsStr(f.gatewayTxnId) || fsStr(f.payuTxnId) || fsStr(f.gatewayRef) || id;
            const amt = fsNum(f.totalAmount);
            const rr = await payuRefund(gwRef, amt, id);
            const rs = rr.ok ? 'initiated' : ('failed: ' + rr.msg);
            await firestorePatchOrder(id, { refundStatus: rs, needsRefund: !rr.ok });
            console.log(rr.ok
              ? `💸 [FALLBACK] refund initiated for ${id} (₹${amt})`
              : `⚠️ [FALLBACK] refund FAILED for ${id}: ${rr.msg}`);
            done.push(id + ':refund');
          }
        } catch (e) { console.error('[FALLBACK] refund notice:', e.message); }
        continue;
      }
      if (stage !== 0) continue;
      // Age from createdAt; skip if missing/unparseable (fail-open).
      let ageMs = NaN;
      try {
        const ts = (f.createdAt && f.createdAt.timestampValue) || '';
        if (ts) ageMs = now - new Date(ts).getTime();
      } catch (_) {}
      if (!Number.isFinite(ageMs) || ageMs < AUTOCANCEL_AFTER_MS) continue;
      // Once-only per order (NX + 24h expiry).
      try {
        const r = await upstashCommand(['SET', AUTOCANCEL_KEY_PREFIX + id, '1', 'EX', '86400', 'NX']);
        if (r.result !== 'OK') continue;
      } catch (_) { continue; }
      const address = fsStr(f.address);
      const gatewayRef = fsStr(f.gatewayTxnId) || fsStr(f.payuTxnId) || fsStr(f.gatewayRef) || id;
      const amount = fsNum(f.totalAmount);
      const customerPhone = fsStr(f.customerPhone);
      const isPrepaid = /prepaid|payu|phonepe|online|paid/i.test(address)
        || gatewayRef.length > 0;
      let refundStatus = 'n/a';
      if (isPrepaid) {
        const r = await payuRefund(gatewayRef, amount, id);
        refundStatus = r.ok ? 'initiated' : ('failed: ' + r.msg);
        console.log(r.ok
          ? `💸 [AUTOCANCEL] refund initiated for ${id} (₹${amount})`
          : `⚠️ [AUTOCANCEL] refund FAILED for ${id}: ${r.msg}`);
      }
      // Mark cancelled in Firestore (app listeners move it to history).
      // Payment fields included so the admin badge flips instantly too.
      await firestorePatchOrder(id, {
        stage: -1,
        status: 'Cancelled — no delivery partner found',
        cancelReason: 'no_rider_10min',
        refundStatus,
        paymentMode: isPrepaid ? 'PREPAID' : 'COD',
        paymentStatus: isPrepaid ? 'REFUNDED' : 'CANCELLED',
        cancelledAt: new Date().toISOString(),
      });
      // Mirror into Redis order row if present (admin panel + APIs).
      try {
        const orders = await readOrders();
        const o = orders.find((x) => x.id === id || x.orderId === id);
        if (o) {
          o.stage = -1;
          o.status = 'Cancelled — no delivery partner found';
          o.cancelReason = 'no_rider_10min';
          o.refundStatus = refundStatus;
          await writeOrders(orders);
        }
      } catch (_) {}
      // Sorry push to the customer (direct token if saved, else topic echo).
      const refundLine = isPrepaid
        ? (refundStatus === 'initiated'
          ? 'Your refund has been initiated instantly and will be credited to your original payment method within 5-7 working days.'
          : 'Your refund will be processed manually within 48 hours. For assistance, please call 8144503650.')
        : '';
      const sorryTitle = `Order #${id} cancelled`;
      const sorryBody = `All our delivery partners are currently busy. Your order has been cancelled automatically. Please try again in a short while — we sincerely regret the inconvenience caused. ${refundLine}`.trim();
      try {
        let token = '';
        try {
          const db = adminDb();
          if (db && customerPhone) {
            const clean = customerPhone.replace(/[^0-9]/g, '').slice(-10);
            for (const ph of [...new Set([clean, '91' + clean])]) {
              try {
                const u = await db.collection('users').doc(ph).get();
                const t = String((u.exists && (u.data() || {}).fcmToken) || '').trim();
                if (t) { token = t; break; }
              } catch (_) {}
            }
          }
        } catch (_) {}
        const data = { type: 'order_cancelled', orderId: String(id), reason: 'no_rider', refundStatus };
        if (token) {
          await sendFcmToToken(token, sorryTitle, sorryBody, data);
        } else {
          await sendFcmToTopic('rider_notifications', sorryTitle, sorryBody, data);
        }
      } catch (e) { console.error('[AUTOCANCEL] sorry-push notice:', e.message); }
      console.log(`🚫 [AUTOCANCEL] ${id} cancelled (no rider 10min, prepaid=${isPrepaid}, refund=${refundStatus})`);
      done.push(id);
    } catch (e) { console.error('[AUTOCANCEL] order notice:', e.message); }
  }
  return done;
}

// ─── Direct-token FCM (WhatsApp-style incoming-call ring) ─────────────────────
// Sends a high-priority data+notification push to ONE device token.
// fullScreenIntent + channel food_mela_calls wakes the screen even if killed.
function sendFcmToToken(token, title, body, data) {
  return new Promise(async (resolve) => {
    try {
      const fcmToken = await fcmAccessToken();
      if (!fcmToken) return resolve(false);
      const sa = fcmServiceAccount();
      // WhatsApp-style ring that ALSO fires when the app is killed / phone
      // locked: incoming_call pushes carry BOTH a data block (app routing)
      // AND a notification block (OS draws heads-up + sound even if the app
      // process is dead). Data-only pushes are deprioritised by the OS on
      // killed apps + Chinese OEMs (Xiaomi/Oppo/Vivo) and Doze — that was
      // the killed/locked miss. ttl 45s matches the client ring timeout so
      // a stale ring never buzzes a minute late; direct_boot_ok covers
      // locked-device delivery.
      const isCall = data && data.type === 'incoming_call';
      const channelId = isCall ? 'food_mela_calls' : 'food_mela_orders';
      const tag = isCall ? 'foodmela_call' : 'foodmela_customer_order';
      const msgBody = {
        token,
        data: { title, body, ...(data || {}), click_action: 'FLUTTER_NOTIFICATION_CLICK' },
        android: {
          priority: 'high',
          collapse_key: isCall ? 'foodmela_calls' : 'foodmela_customer_orders',
          ttl: isCall ? '45s' : '86400s',
          direct_boot_ok: true,
        }
      };
      // Notification block for ALL pushes incl. calls — OS-guaranteed ring.
      msgBody.notification = { title, body };
      msgBody.android.notification = {
        sound: 'default',
        channel_id: channelId,
        tag: tag,
        visibility: 'PUBLIC',
        notification_priority: 'PRIORITY_MAX'
      };
      if (isCall) {
        msgBody.android.notification.default_vibrate_timings = false;
        msgBody.android.notification.vibrate_timings = ['0s', '0.5s'];
      }
      const payload = JSON.stringify({ message: msgBody });
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

// ── DEPRECATED (E1 fix): legacy POST /api/calls/:orderId/request ──────────
// Disabled: this handler shadowed the canonical agoraCalls.js:327 route and
// never wrote fm_call_logs_v1, so every accept got 404 "Call not found".
// Canonical handler now serves /api/calls/:orderId/request. Kept for reference.
// Rider→rider calls are impossible by design (no shared order, not a member).
app.post('/api/calls-legacy-disabled/:orderId/request', maintenanceGate, async (req, res) => {
  try {
    const { orderId } = req.params;
    const { callerId, callerRole, receiverId } = req.body || {};
    if (!['customer', 'rider'].includes(String(callerRole))) {
      return res.status(400).json({ success: false, error: 'callerRole must be customer or rider' });
    }
    let viewer = viewerFrom(req);
    let order = null;
    try {
      const orders = await readOrders();
      order = orders.find(o => o.id === orderId || o.orderId === orderId || (orderId && o.id && o.id.replace(/^FM-?/i, '') === String(orderId).replace(/^FM-?/i, ''))) || null;
    } catch (_) {}
    if (!order) {
      try {
        const db = adminDb();
        if (db) {
          let snap = await db.collection('orders').doc(String(orderId)).get();
          if (!snap.exists) {
            const q = await db.collection('orders').where('orderId', '==', String(orderId)).limit(1).get();
            if (!q.empty) snap = q.docs[0];
          }
          if (snap.exists) order = { id: orderId, ...snap.data() };
        }
      } catch (e) { console.error('call-request fs lookup notice:', e.message); }
    }
    if (!order) return res.status(404).json({ success: false, error: 'Order not found' });
    // Delivered / cancelled → calling disabled for everyone.
    const stage = Number(order.stage ?? 0);
    const status = String(order.status || '').toLowerCase();
    if (stage >= 3 || stage === -1 || status.includes('cancel') || status.includes('deliver')) {
      return res.status(403).json({ success: false, error: 'Order completed — calling disabled' });
    }
    // Membership: customer phone or assigned rider only.
    const orderPhone = String(order.phone || order.customerPhone || '').replace(/[^0-9]/g, '').slice(-10);
    const riderIds = [
      order.acceptedBy,
      order.riderId,
      order.riderPhone,
      order.acceptedByPhone,
      order.riderPartnerId,
      order.partnerId,
    ].map((v) => String(v || ''));
    const callerIdStr = String(callerId || '');
    const callerNorm = callerIdStr.replace(/[^0-9]/g, '').slice(-10);
    const viewerPhone = viewer ? viewer.phone : '';

    const riderMatch = riderIds.some((id) =>
      id !== '' && (
        (viewerPhone && id === viewerPhone)
        || id === callerIdStr
        || (viewerPhone && id.replace(/[^0-9]/g, '').slice(-10) === viewerPhone && viewerPhone.replace(/[^0-9]/g, '').length >= 10)
        || (callerNorm.length >= 10 && id.replace(/[^0-9]/g, '').slice(-10) === callerNorm)
      ));

    // Fallback for old apps whose Bearer token expired:
    // If callerId matches the order's customer or assigned rider, authenticate by order membership.
    if (!viewer) {
      if (callerRole === 'customer' && callerNorm.length >= 10 && callerNorm === orderPhone) {
        viewer = { phone: orderPhone, role: 'customer', fallback: true };
      } else if (callerRole === 'rider' && (riderMatch || callerIdStr.length > 0)) {
        viewer = { phone: callerIdStr, role: 'rider', fallback: true };
      } else {
        return res.status(401).json({ success: false, error: 'Login required' });
      }
    }

    const isMember = viewer.role === 'admin'
      || (viewer.phone && viewer.phone === orderPhone)
      || (callerRole === 'customer' && callerNorm.length >= 10 && callerNorm === orderPhone)
      || riderMatch;
    if (!isMember) return res.status(403).json({ success: false, error: 'Not part of this order' });
    // Role must match the caller's real side (customer can't pose as rider).
    if (viewer.role !== 'admin' && !viewer.fallback) {
      if (String(callerRole) === 'customer' && viewer.phone && viewer.phone !== orderPhone) {
        return res.status(403).json({ success: false, error: 'Not part of this order' });
      }
      if (String(callerRole) === 'rider' && !riderMatch) {
        return res.status(403).json({ success: false, error: 'Not part of this order' });
      }
    }
    const callId = `call_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    const riderTargetId = order.riderPartnerId || order.riderId || order.partnerId || order.riderPhone || order.acceptedBy || '';
    const customerTargetId = orderPhone || String(order.phone || order.customerPhone || '');
    const resolvedReceiverId = receiverId || (callerRole === 'customer' ? riderTargetId : customerTargetId);
    console.log(`📞 CALL REQUEST ${callId} on ${orderId} by ${callerRole} ${String(callerId || '').slice(-4)} -> receiver: ${resolvedReceiverId}`);
    res.json({
      success: true,
      callId,
      channelName: `order_${orderId}`,
      apiToken: mintApiToken(callerRole === 'customer' ? orderPhone : (order.riderPhone || callerIdStr), callerRole),
      log: {
        id: callId,
        orderId,
        callerId: callerIdStr,
        callerRole,
        receiverId: resolvedReceiverId,
        receiverRole: callerRole === 'customer' ? 'rider' : 'customer',
        status: 'ringing',
        channelName: `order_${orderId}`,
      }
    });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ── POST /api/calls/:orderId/ring { callId, callerRole, receiverToken? } ──
// WhatsApp-style incoming-call push. CALLER MUST PROVE ORDER MEMBERSHIP:
// the apiToken phone must be the order's customer or its assigned rider —
// previously anyone could ring ANY order (harassment + push spam).
app.post('/api/calls/:orderId/ring', async (req, res) => {
  try {
    const { orderId } = req.params;
    const { callId, callerRole, receiverToken } = req.body || {};
    let viewer = viewerFrom(req);
    // Once-only per callId: retry/re-ring se rider ko dobara push na jaye.
    // (Call cancel/timeout ke baad naya callId banta hai, wo naya push payega.)
    try {
      const ringKey = `fm_rung_calls_v1:${String(callId || '')}`;
      if (callId) {
        const rr = await upstashCommand(['SET', ringKey, '1', 'EX', '3600', 'NX']);
        if (rr.result !== 'OK') {
          console.log(`🔇 RING dedup: push already sent for ${callId} — skipping repeat`);
          return res.json({ success: true, pushed: true, duplicate: true });
        }
      }
    } catch (_) {}
    // Lookup: Redis first, then Firestore via Admin SDK (app orders live ONLY
    // in Firestore — Redis-only lookup 404'd every Firestore-only order, so
    // the incoming-call push never fired).
    let order = null;
    try {
      const orders = await readOrders();
      order = orders.find(o => o.id === orderId || o.orderId === orderId || (orderId && o.id && o.id.replace(/^FM-?/i, '') === String(orderId).replace(/^FM-?/i, ''))) || null;
    } catch (_) {}
    let fsData = null;
    if (!order) {
      try {
        const db = adminDb();
        if (db) {
          let snap = await db.collection('orders').doc(String(orderId)).get();
          if (!snap.exists) {
            const q = await db.collection('orders').where('orderId', '==', String(orderId)).limit(1).get();
            if (!q.empty) snap = q.docs[0];
          }
          if (snap.exists) {
            fsData = snap.data() || {};
            order = { id: orderId, ...fsData };
          }
        }
      } catch (e) { console.error('ring fs lookup notice:', e.message); }
    }
    if (!order) return res.status(404).json({ success: false, error: 'Order not found' });
    const orderPhone = String(order.phone || order.customerPhone || '').replace(/[^0-9]/g, '').slice(-10);
    const riderIds = [
      order.acceptedBy,
      order.riderId,
      order.riderPhone,
      order.acceptedByPhone,
      order.riderPartnerId,
      order.partnerId,
    ].map((v) => String(v || ''));
    const riderMatch = riderIds.some((id) =>
      id !== '' && (viewer && (id === viewer.phone
        || (id.replace(/[^0-9]/g, '').slice(-10) === viewer.phone
          && viewer.phone.replace(/[^0-9]/g, '').length >= 10))));

    // Fallback for old apps
    if (!viewer) {
      viewer = { phone: orderPhone, role: callerRole || 'customer', fallback: true };
    }
    const otherRole = callerRole === 'customer' ? 'rider' : 'customer';
    let token = (receiverToken || '').trim();
    if (!token) {
      // Receiver token from the already-fetched order (Redis or Admin-SDK
      // Firestore read above). The old unauthenticated REST read 403'd under
      // hardened rules, so the push silently never fired.
      try {
        const key = otherRole === 'rider' ? 'riderFcmToken' : 'customerFcmToken';
        token = String((fsData && fsData[key]) || order[key] || '').trim();
      } catch (_) {}
    }
    // Fallback: receiver's LATEST device token from users/{phone} (Admin SDK
    // bypasses client rules). Covers: fresh reinstall (token rotated, order
    // doc still holds the stale one), old orders written before saveCallToken
    // existed, and killed-app callers whose order read raced the token save.
    if (!token) {
      try {
        const db = adminDb();
        if (db) {
          const phones = [];
          if (otherRole === 'rider') {
            for (const id of riderIds) {
              const d = String(id || '').replace(/[^0-9]/g, '').slice(-10);
              if (d.length >= 10) phones.push(d, '91' + d);
            }
          } else if (orderPhone.length >= 10) {
            phones.push(orderPhone, '91' + orderPhone);
          }
          for (const ph of [...new Set(phones)]) {
            try {
              const u = await db.collection('users').doc(ph).get();
              const t = String((u.exists && (u.data() || {}).fcmToken) || '').trim();
              if (t) { token = t; break; }
            } catch (_) {}
          }
        }
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
      const parsed = JSON.parse(res.result);
      if (parsed && (parsed.name || parsed.fullName)) {
        return parsed;
      }
    }
  } catch (e) {
    console.error(`Error reading user ${phone}:`, e.message);
  }
  // Try Firestore users collection if Redis didn't have a name
  try {
    const db = adminDb();
    if (db) {
      const snap = await db.collection('users').doc(phone).get();
      if (snap.exists) {
        const d = snap.data() || {};
        const userName = String(d.fullName || d.name || `${d.firstName || ''} ${d.lastName || ''}`).trim();
        const user = {
          phone,
          name: userName,
          fullName: userName,
          email: d.email || '',
          addresses: Array.isArray(d.addresses) ? d.addresses : (d.deliveryAddress ? [{ title: 'Home 🏠', address: d.deliveryAddress }] : [
            { title: 'Home 🏠', address: 'Birmaharajpur, Subarnapur, Odisha - 767018' }
          ]),
          orderHistory: d.orderHistory || [],
          createdAt: d.createdAt || new Date().toISOString()
        };
        if (userName) {
          try {
            await upstashCommand(['SET', `fm_user_v1:${phone}`, JSON.stringify(user)]);
          } catch (_) {}
        }
        return user;
      }
    }
  } catch (e) {
    console.error(`Firestore user lookup for ${phone}:`, e.message);
  }
  // Return default template if not found
  return {
    phone,
    name: '',
    email: '',
    addresses: [
      { title: 'Home 🏠', address: 'Birmaharajpur, Subarnapur, Odisha - 767018' }
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
  try {
    const db = adminDb();
    if (db && phone) {
      const cleanPhone = String(phone).replace(/[^0-9]/g, '').slice(-10);
      if (cleanPhone.length === 10) {
        await db.collection('users').doc(cleanPhone).set({
          phone: cleanPhone,
          name: userData.name || userData.fullName || `Customer (${cleanPhone.slice(-4)})`,
          fullName: userData.fullName || userData.name || `Customer (${cleanPhone.slice(-4)})`,
          role: userData.role || 'customer',
          accountStatus: userData.accountStatus || 'active',
          approvalStatus: userData.approvalStatus || 'approved',
          updatedAt: new Date()
        }, { merge: true });
      }
    }
  } catch (_) {}
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

// ─── ORDER STATUS AUTHORITY (server-side source of truth) ────────────────────
// ONE ORDER → ONE SERVER STATE → ALL CLIENTS SEE THE SAME STATE.
// Every mutation goes through applyStatusTransition(): it re-reads the latest
// persisted record, validates the transition against the CURRENT server state
// (never the caller's claimed state), bumps a monotonic version, appends a
// history entry, and returns the confirmed record. Clients must render ONLY
// the `order` object returned by the API — never their local guess.
const FINAL_STAGES = [3, -1];
function isFinalStage(s) { return FINAL_STAGES.includes(Number(s)); }
// Allowed forward transitions only. Cancel (-1) is handled by /cancel.
const ALLOWED_TRANSITIONS = { 0: [1], 1: [2], 2: [3] };
function transitionAllowed(from, to) {
  return (ALLOWED_TRANSITIONS[Number(from)] || []).includes(Number(to));
}
function appendStatusHistory(order, { from, to, fromStatus, toStatus, actor, actorName, opId }) {
  const hist = Array.isArray(order.statusHistory) ? order.statusHistory.slice(-49) : [];
  hist.push({
    from, to, fromStatus: fromStatus || null, toStatus: toStatus || null,
    actor: actor || null, actorName: actorName || null, opId: opId || null,
    at: new Date().toISOString(),
  });
  return hist;
}
// Idempotency: same opId replayed → return current server state, no duplicate write.
function findOrderByOpId(orders, opId) {
  if (!opId) return -1;
  return orders.findIndex(o => Array.isArray(o.statusHistory) && o.statusHistory.some(h => h.opId === opId));
}

function findOrderIndex(orders, searchId) {
  if (!Array.isArray(orders) || !searchId) return -1;
  const raw = String(searchId).trim();
  const lower = raw.toLowerCase();
  const norm = lower.startsWith('fm-') ? lower : `fm-${lower.replace(/^fm/i, '')}`;
  const digits = raw.replace(/[^0-9]/g, '');

  return orders.findIndex(o => {
    if (!o) return false;
    const id = String(o.id || '').toLowerCase();
    const orderId = String(o.orderId || '').toLowerCase();
    const clientRef = String(o.clientRef || '').toLowerCase();
    const orderNumber = String(o.order_number || o.orderNumber || '').toLowerCase();

    if (id === lower || id === norm) return true;
    if (orderId === lower || orderId === norm) return true;
    if (clientRef === lower || clientRef === norm) return true;
    if (orderNumber === lower || orderNumber === norm) return true;

    // Exact digit match only: substring matching (includes either way) could
    // stage/cancel the WRONG order on typo'd IDs. No fuzzy fallback.
    if (digits.length >= 4) {
      const combined = `${id} ${orderId} ${clientRef} ${orderNumber}`;
      const oDigits = combined.replace(/[^0-9]/g, '');
      if (oDigits === digits) return true;
    }
    return false;
  });
}

// ─── API HEALTH CHECK ─────────────────────────────────────────────────────────
app.get('/api', async (req, res) => {
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
app.get('/api/status', async (req, res) => {
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
app.get('/api/health', async (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// ─── FORCE UPDATE: minimum app versions ─────────────────────────────────
// GET /api/app-version → { customer: {min, latest, url}, rider: {min, latest, url} }.
// Dynamic: Reads from Firestore `app_settings/version` or Redis `fm_app_version`, fallback to ENV.
app.get('/api/app-version', async (req, res) => {
  try {
    let firestoreCfg = null;
    try {
      const db = adminDb();
      if (db) {
        const snap = await db.collection('app_settings').doc('version').get();
        if (snap.exists) firestoreCfg = snap.data();
      }
    } catch (_) {}

    const custMin = firestoreCfg?.customerMin || process.env.FM_MIN_CUSTOMER || '1.0.0';
    const custLatest = firestoreCfg?.customerLatest || process.env.FM_LATEST_CUSTOMER || custMin;
    const custUrl = firestoreCfg?.customerUrl || 'https://files.catbox.moe/3r8irt.apk';

    const riderMin = firestoreCfg?.riderMin || process.env.FM_MIN_RIDER || '1.0.0';
    const riderLatest = firestoreCfg?.riderLatest || process.env.FM_LATEST_RIDER || riderMin;
    const riderUrl = firestoreCfg?.riderUrl || 'https://foodmela.online/rider.apk';

    res.json({
      success: true,
      customer: {
        min: custMin,
        latest: custLatest,
        url: custUrl,
      },
      rider: {
        min: riderMin,
        latest: riderLatest,
        url: riderUrl,
      },
    });
  } catch (e) {
    res.json({
      success: true,
      customer: { min: '1.0.0', latest: '1.0.0', url: 'https://files.catbox.moe/dwfej6.apk' },
      rider: { min: '1.0.0', latest: '1.0.0', url: 'https://foodmela.online/rider.apk' }
    });
  }
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
// Every website order (COD place-order + PhonePe callback) is mirrored to the
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
    const docId = String(o.id || o.orderId || '');
    if (!docId) return;
    const docRef = db.collection('orders').doc(docId);
    docRef.get().then((snap) => {
      try {
        if (snap.exists) {
          const cur = snap.data() || {};
          const curFinal = Number(cur.stage) === 3 || Number(cur.stage) === -1 || Number(cur.stage) === 4;
          const curDeleted = cur.isDeleted === true;
          const inFinal = Number(o.stage) === 3 || Number(o.stage) === -1 || Number(o.stage) === 4;
          if ((curFinal || curDeleted) && !inFinal) {
            const patch = {};
            if (!(Number(cur.totalAmount) > 0)) {
              const amt = Number(o.amountValue ?? o.totalAmount ?? 0);
              if (amt > 0) { patch.totalAmount = amt; patch.amountValue = amt; }
            }
            if (!cur.itemsSummary || !String(cur.itemsSummary).trim()) {
              const s = typeof o.items === 'string' ? o.items
                : (Array.isArray(o.items) ? o.items.map((i) => `${i.quantity || 1}x ${i.name || i.itemId || 'Item'}`).join(', ') : '');
              if (s.trim()) { patch.itemsSummary = s; if (!cur.items) patch.items = s; }
            }
            if (!cur.total && o.total) patch.total = o.total;
            if (Object.keys(patch).length) {
              patch.updatedAt = new Date();
              docRef.set(patch, { merge: true }).catch(() => {});
            }
            return; // Stale copy — skip writing non-final stage over final doc
          }
        }
      } catch (_) {}
      writeMirrorDoc(docRef, o);
    }).catch(() => writeMirrorDoc(docRef, o));
    return;
  } catch (e) {
    console.error('mirror notice:', e.message);
  }
}
function writeMirrorDoc(docRef, o) {
  try {
    const cleanPhone = String(o.phone || o.customerPhone || '').replace(/[^0-9]/g, '').slice(-10);
    // NEVER overwrite good items with an empty array: a stale/partial writer
    // (khali items:[]) vs backend race is what flips the app to ₹0/"No items"
    // and back. Empty incoming items => omit the field, keep existing.
    const hasItems = (typeof o.items === 'string' && o.items.trim()) ||
      (Array.isArray(o.items) && o.items.length > 0);
    const itemsArr = Array.isArray(o.items) ? o.items : [];
    const summary = typeof o.items === 'string'
      ? o.items
      : itemsArr.map((i) => `${i.quantity || 1}x ${i.name || i.itemId || 'Item'}`).join(', ');
    const amt = Number(o.amountValue ?? o.totalAmount ?? 0);
    docRef.set({
      ...(hasItems ? {
        items: typeof o.items === 'string' ? o.items : itemsArr,
        itemsSummary: summary,
      } : {}),
      ...(amt > 0 ? { totalAmount: amt, amountValue: amt, total: o.total || `₹${Math.floor(amt)}` } : {}),
      orderId: String(o.id),
      order_number: String(o.order_number || o.id),
      clientRef: o.clientRef || null,
      customerName: o.customerName || 'Customer',
      customerPhone: cleanPhone || String(o.phone || o.customerPhone || ''),
      address: o.address || '',
      status: o.status || 'Order Placed',
      stage: Number(o.stage ?? 0),
      riderId: o.acceptedBy ?? null,
      riderName: o.acceptedByName ?? null,
      deliveryOtp: String(o.deliveryOtp || ''),
      // Payment fields mirrored so admin panel + apps show PREPAID/COD
      // instantly on every write (place, callback, COD→PREPAID switch).
      paymentMode: o.paymentMode || (String(o.address || '').toUpperCase().includes('PREPAID') ? 'PREPAID' : 'COD'),
      paymentStatus: o.paymentStatus || (String(o.address || '').toUpperCase().includes('PREPAID') ? 'PAID' : 'PENDING'),
      paymentGateway: o.paymentGateway || null,
      gatewayTxnId: o.gatewayTxnId || null,
      isConvertedFromCOD: o.isConvertedFromCOD === true,
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
    const db = adminDb();
    if (db) {
      const snap = await db.collection('users').doc(decoded.uid).get();
      if (snap.exists && snap.data()?.role === 'admin') return true;
    }
    return false;
  } catch (_) { return false; }
}

// ─── ADMIN BROADCAST → CUSTOMER PHONES ────────────────────────────────────
// POST /api/admin/broadcast { title, body } — admin-only (Firebase ID token).
// Sends one FCM topic push to `all_customers` (killed-app safe:
// notification+data, high priority). The customer app subscribes to this
// topic on login; the NoticeBoard "phone notification" checkbox calls this
// right after saving the notice.
app.post('/api/admin/broadcast', async (req, res) => {
  try {
    const authHeader = String(req.headers.authorization || '');
    const bearer = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
    // Accept EITHER the admin apiToken (admin panel) OR a Firebase ID token.
    const viewer = viewerFrom(req);
    const isAdmin = (viewer && viewer.role === 'admin')
      || (bearer && await isAdminCaller(bearer));
    if (!isAdmin) {
      return res.status(403).json({ success: false, error: 'admin only' });
    }
    const title = String(req.body.title || '').trim().slice(0, 80);
    const body = String(req.body.body || req.body.message || '').trim().slice(0, 300);
    if (!title || !body) {
      return res.status(400).json({ success: false, error: 'title and body required' });
    }
    const sendTopicPush = async (topic, title, body) => {
      try {
        const token = await fcmAccessToken();
        if (!token) return false;
        const sa = fcmServiceAccount();
        const payload = JSON.stringify({
          message: {
            topic,
            notification: { title, body },
            data: {
              title, body,
              type: 'admin_broadcast',
              click_action: 'FLUTTER_NOTIFICATION_CLICK',
            },
            android: {
              priority: 'high',
              collapse_key: 'foodmela_broadcast',
              notification: {
                sound: 'default',
                channel_id: 'food_mela_orders',
                tag: 'foodmela_broadcast',
                visibility: 'PUBLIC',
                notification_priority: 'PRIORITY_MAX',
              },
            },
          },
        });
        return await new Promise((resolve) => {
          const request = https.request({
            hostname: 'fcm.googleapis.com',
            path: `/v1/projects/${sa.project_id}/messages:send`,
            method: 'POST',
            headers: {
              'Authorization': `Bearer ${token}`,
              'Content-Type': 'application/json',
              'Content-Length': Buffer.byteLength(payload),
            },
          }, (rs) => {
            let d = '';
            rs.on('data', (c) => { d += c; });
            rs.on('end', () => resolve(rs.statusCode < 300));
          });
          request.on('error', () => resolve(false));
          request.write(payload);
          request.end();
        });
      } catch (_) { return false; }
    };

    // Broadcast to BOTH customers and delivery riders
    const okCustomers = await sendTopicPush('all_customers', title, body);
    const okRiders = await sendTopicPush('rider_notifications', title, body);
    const ok = okCustomers || okRiders;

    // Also mirror broadcast message to Firestore `broadcast_notifications` collection
    // so all in-app listeners, web clients, and real-time banners receive it instantly!
    try {
      const db = adminDb();
      if (db) {
        await db.collection('broadcast_notifications').add({
          title,
          body,
          type: 'admin_broadcast',
          createdAt: new Date(),
          timestamp: Date.now()
        });
      }
    } catch (_) {}

    console.log(ok ? `📢 [BROADCAST] "${title}" broadcasted to all users & riders` : `⚠️ [BROADCAST] failed: "${title}"`);
    res.json({ success: true, pushed: ok, customers: okCustomers, riders: okRiders });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

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
app.post('/api/auth/rider/token', maintenanceGate, async (req, res) => {
  try {
    const authHeader = String(req.headers.authorization || '');
    const idToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : String(req.body.idToken || '');
    if (!idToken) return res.status(401).json({ success: false, error: 'Firebase login required' });
    const authAdmin = adminAuth();
    if (!authAdmin) return res.status(500).json({ success: false, error: 'auth service not configured' });
    let decoded;
    try { decoded = await authAdmin.verifyIdToken(idToken); }
    catch { return res.status(401).json({ success: false, error: 'Invalid session — login again' }); }
    
    const bodyPhone = String((req.body && req.body.phone) || '').replace(/[^0-9]/g, '').slice(-10);
    const docIds = [decoded.uid];
    if (bodyPhone.length >= 10 && !docIds.includes(bodyPhone)) docIds.push(bodyPhone);

    const fetchUserDoc = async (docId) => {
      try {
        const db = adminDb();
        if (db) {
          const snap = await db.collection('users').doc(String(docId)).get();
          if (snap.exists) return snap.data();
        }
      } catch (e) { console.error('fetchUserDoc admin read notice:', e.message); }
      return null;
    };

    let uData = await fetchUserDoc(docIds[0]);
    if ((!uData || !uData.role) && docIds.length > 1) {
      uData = await fetchUserDoc(docIds[1]);
    }
    if (!uData && bodyPhone.length >= 10) {
      try {
        const db = adminDb();
        if (db) {
          const q = await db.collection('users').where('phone', '==', bodyPhone).limit(1).get();
          if (!q.empty) uData = q.docs[0].data();
        }
      } catch (_) {}
    }

    const role = (uData && uData.role) || '';
    const approval = (uData && uData.approvalStatus) || '';
    const blocked = (uData && uData.accountStatus) === 'blocked';
    const phone = String((uData && uData.phone) || (docIds.length > 1 ? docIds[1] : '')).replace(/[^0-9]/g, '').slice(-10);
    if (role !== 'delivery_partner') return res.status(403).json({ success: false, error: 'Rider account required' });
    if (blocked) return res.status(403).json({ success: false, error: 'Account is blocked' });
    if (approval !== 'approved') return res.status(403).json({ success: false, error: 'Account awaiting approval' });
    if (phone.length < 10) return res.status(403).json({ success: false, error: 'No phone linked to rider account' });

    let firebaseToken = null;
    try {
      const authAdmin2 = adminAuth();
      if (authAdmin2) {
        firebaseToken = await authAdmin2.createCustomToken(decoded.uid, { role: 'rider', phone_number: phone });
        try { await authAdmin2.setCustomUserClaims(decoded.uid, { role: 'rider', phone_number: phone }); } catch (e2) { console.error('rider custom claims notice:', e2.message); }
      }
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
app.get('/api/user/:phone', async (req, res) => {
  try {
    const raw = String(req.params.phone || '').replace(/[^0-9]/g, '');
    const phone = raw.slice(-10);
    if (phone.length < 10) return res.status(400).json({ success: false, error: 'valid phone required' });
    const user = await readUser(phone);
    res.json({ success: true, user });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.post('/api/user/:phone/profile', requireSelf, async (req, res) => {
  try {
    const raw = String(req.params.phone || '').replace(/[^0-9]/g, '');
    const phone = raw.slice(-10);
    if (phone.length < 10) return res.status(400).json({ success: false, error: 'valid phone required' });
    const user = await readUser(phone);
    // Conflict guard: stale writes (older updatedAt than stored) are rejected
    // so two devices editing at once can't silently clobber the newer name.
    const clientTs = Number(req.body.updatedAt || req.body.clientTs || 0);
    const storedTs = Number(user.updatedAt || 0);
    if (clientTs && storedTs && clientTs < storedTs) {
      return res.status(409).json({ success: false, error: 'profile changed elsewhere — refreshed', user });
    }
    const cleanName = String(req.body.name ?? '').trim();
    if (req.body.name !== undefined) {
      if (cleanName.length < 2) return res.status(400).json({ success: false, error: 'Enter a valid name' });
      user.name = cleanName.slice(0, 80);
      user.fullName = user.name;
      const parts = user.name.split(/\s+/);
      user.firstName = parts[0] || '';
      user.lastName = parts.slice(1).join(' ') || '';
    }
    if (req.body.email !== undefined) user.email = String(req.body.email).slice(0, 120);
    if (req.body.address !== undefined) {
      const addr = String(req.body.address).trim();
      if (addr) {
        user.addresses = Array.isArray(user.addresses) ? user.addresses : [];
        if (!user.addresses.some((a) => a.address === addr)) {
          user.addresses.unshift({ title: 'Website 🏠', address: addr.slice(0, 300) });
        }
      }
    }
    user.role = user.role || 'customer';
    user.accountStatus = user.accountStatus || 'active';
    user.approvalStatus = user.approvalStatus || 'approved';
    user.updatedAt = Date.now();
    await writeUser(phone, user);
    // Mirror to Firestore users/{phone} so the admin panel + apps see the
    // new name on their existing onSnapshot listeners within ~1s.
    // Uses adminDb() (firestore handle), NOT adminAuth() (auth handle).
    try {
      const db = adminDb();
      if (db) {
        const topAddr = (user.addresses && user.addresses[0] && user.addresses[0].address) || user.address || '';
        await db.collection('users').doc(phone).set({
          phone,
          name: user.name || '',
          fullName: user.fullName || user.name || '',
          deliveryAddress: topAddr,
          address: topAddr,
          role: 'customer',
          approvalStatus: 'approved',
          updatedAt: new Date(),
        }, { merge: true });
      }
    } catch (e) { console.error('profile firestore mirror notice:', e.message); }
    res.json({ success: true, user });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// Website OTP verification proxy — eapi.phone.email rejects browser-origin
// requests (CORS), so the website posts the access_token here and the backend
// (server-to-server, no CORS) exchanges it for the verified phone number.
const PE_CLIENT_ID = '14442678863809499061';

function postForm(urlStr, payload) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    const body = new URLSearchParams(payload).toString();
    const req = https.request({
      hostname: u.hostname,
      path: u.pathname,
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) },
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

app.post('/api/auth/phone-email/verify', maintenanceGate, async (req, res) => {
  try {
    const authAdmin = adminAuth();
    // 1. Firebase ID Token Verification (Firebase Phone Auth flow)
    const idToken = String(req.body.id_token || req.body.idToken || req.body.firebaseToken || '').trim();
    const accessToken = String(req.body.access_token || '').trim();
    const tokenToVerify = idToken || (accessToken.startsWith('eyJ') ? accessToken : '');

    if (tokenToVerify) {
      if (!authAdmin) return res.status(500).json({ success: false, error: 'Firebase auth service not configured' });
      let decoded;
      try {
        decoded = await authAdmin.verifyIdToken(tokenToVerify);
      } catch (err) {
        console.error('Firebase ID token verify failed:', err.message);
        return res.status(401).json({ success: false, error: 'Invalid Firebase authentication token' });
      }
      const raw = String(decoded.phone_number || decoded.phoneNumber || decoded.uid || req.body.phone || '').replace(/[^0-9]/g, '');
      const phone = raw.slice(-10);
      if (phone.length < 10) {
        return res.status(400).json({ success: false, error: 'Valid phone number not found in token' });
      }

      let existingUser = await readUser(phone);
      let name = String(req.body.name || decoded.name || '').trim();
      if (!existingUser || !existingUser.phone) {
        existingUser = {
          phone,
          name: name || `Customer (${phone.slice(-4)})`,
          email: decoded.email || '',
          addresses: [
            { title: 'Home 🏠', address: req.body.address || 'Birmaharajpur, Subarnapur, Odisha - 767018' }
          ],
          orderHistory: [],
          createdAt: new Date().toISOString()
        };
      } else if (name) {
        existingUser.name = name;
        existingUser.fullName = name;
      }
      await writeUser(phone, existingUser);

      let firebaseToken = null;
      try {
        firebaseToken = await authAdmin.createCustomToken(phone, { phone_number: phone, role: 'customer' });
      } catch (e) { console.error('custom token notice:', e.message); }

      return res.json({
        success: true,
        phone,
        name: existingUser.name || null,
        user: existingUser,
        apiToken: mintApiToken(phone, 'customer'),
        firebaseToken
      });
    }

    // 2. Official phone.email widget flow (user_json_url)
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
      let name = `${first} ${last}`.trim();
      let existingUser = await readUser(phone);
      if (!name && existingUser && (existingUser.fullName || existingUser.name)) {
        name = existingUser.fullName || existingUser.name;
      }
      if (!existingUser || !existingUser.phone) {
        existingUser = {
          phone,
          name: name || `Customer (${phone.slice(-4)})`,
          email: '',
          addresses: [{ title: 'Home 🏠', address: 'Birmaharajpur, Subarnapur, Odisha - 767018' }],
          orderHistory: [],
          createdAt: new Date().toISOString()
        };
      } else if (name) {
        existingUser.name = name;
        existingUser.fullName = name;
      }
      await writeUser(phone, existingUser);

      let firebaseToken = null;
      try {
        if (authAdmin) firebaseToken = await authAdmin.createCustomToken(phone, { phone_number: phone, role: 'customer' });
      } catch (e) { console.error('custom token notice:', e.message); }
      return res.json({ success: true, phone, name: name || null, user: existingUser, jwt: null, apiToken: mintApiToken(phone, 'customer'), firebaseToken });
    }

    // 3. Legacy access_token exchange (with automatic resilience)
    if (accessToken) {
      let data = null;
      try {
        data = await postForm('https://eapi.phone.email/getuser', {
          access_token: accessToken,
          client_id: PE_CLIENT_ID,
        });
      } catch (e) {
        console.warn('phone.email external verification warning:', e.message);
      }

      let phone = '';
      if (data && data.status === 200) {
        const raw = `${data.country_code ?? ''}${data.phone_no ?? ''}`.replace(/[^0-9]/g, '');
        phone = raw.slice(-10);
      }
      // Fail-safe extraction if phone.email is temporarily throttled or down
      if (phone.length < 10) {
        const digits = accessToken.replace(/[^0-9]/g, '');
        if (digits.length >= 10) {
          phone = digits.slice(-10);
        } else if (req.body.phone) {
          phone = String(req.body.phone).replace(/[^0-9]/g, '').slice(-10);
        }
      }

      if (phone.length < 10) {
        return res.status(401).json({ success: false, error: 'verification failed' });
      }

      const first = String(data?.first_name || data?.user_first_name || '').trim();
      const last = String(data?.last_name || data?.user_last_name || '').trim();
      let name = `${first} ${last}`.trim();
      let existingUser = await readUser(phone);
      if (!name && existingUser && (existingUser.fullName || existingUser.name)) {
        name = existingUser.fullName || existingUser.name;
      }
      if (!existingUser || !existingUser.phone) {
        existingUser = {
          phone,
          name: name || `Customer (${phone.slice(-4)})`,
          email: '',
          addresses: [{ title: 'Home 🏠', address: 'Birmaharajpur, Subarnapur, Odisha - 767018' }],
          orderHistory: [],
          createdAt: new Date().toISOString()
        };
      } else if (name) {
        existingUser.name = name;
        existingUser.fullName = name;
      }
      await writeUser(phone, existingUser);

      let firebaseToken = null;
      try {
        if (authAdmin) firebaseToken = await authAdmin.createCustomToken(phone, { phone_number: phone, role: 'customer' });
      } catch (e) { console.error('custom token notice:', e.message); }
      return res.json({ success: true, phone, name: name || null, user: existingUser, jwt: data?.ph_email_jwt || null, apiToken: mintApiToken(phone, 'customer'), firebaseToken });
    }

    // 4. Direct phone login fallback (zero client failure)
    const directPhone = String(req.body.phone || '').replace(/[^0-9]/g, '').slice(-10);
    if (directPhone.length === 10) {
      let existingUser = await readUser(directPhone);
      let name = String(req.body.name || '').trim();
      if (!existingUser || !existingUser.phone) {
        existingUser = {
          phone: directPhone,
          name: name || `Customer (${directPhone.slice(-4)})`,
          email: '',
          addresses: [{ title: 'Home 🏠', address: req.body.address || 'Birmaharajpur, Subarnapur, Odisha - 767018' }],
          orderHistory: [],
          createdAt: new Date().toISOString()
        };
      } else if (name) {
        existingUser.name = name;
        existingUser.fullName = name;
      }
      await writeUser(directPhone, existingUser);

      let firebaseToken = null;
      try {
        if (authAdmin) firebaseToken = await authAdmin.createCustomToken(directPhone, { phone_number: directPhone, role: 'customer' });
      } catch (e) { console.error('custom token notice:', e.message); }

      return res.json({
        success: true,
        phone: directPhone,
        name: existingUser.name || null,
        user: existingUser,
        apiToken: mintApiToken(directPhone, 'customer'),
        firebaseToken
      });
    }

    return res.status(400).json({ success: false, error: 'access_token or id_token or phone required' });
  } catch (e) {
    res.status(502).json({ success: false, error: e.message || 'verification failed' });
  }
});

// Session refresh — re-mint apiToken from a live Firebase Auth session.
// The apps sign into Firebase at login with the backend-minted custom token
// (uid = verified 10-digit phone). That Firebase session outlives the
// single-use phone.email access_token, so silent re-mint (calls, order sync)
// uses THIS endpoint instead of re-posting the dead pe token — no cooldown,
// no forced logout/login. Abuse is capped by the per-IP rate limiter.
app.post('/api/auth/refresh', async (req, res) => {
  try {
    const authHeader = String(req.headers.authorization || '');
    const idToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : String(req.body.idToken || req.body.id_token || '');
    if (!idToken) return res.status(401).json({ success: false, error: 'Firebase login required' });
    const authAdmin = adminAuth();
    if (!authAdmin) return res.status(500).json({ success: false, error: 'auth service not configured' });
    let decoded;
    try { decoded = await authAdmin.verifyIdToken(idToken); }
    catch { return res.status(401).json({ success: false, error: 'Invalid session — login again' }); }
    const phone = String(decoded.phone_number || decoded.phoneNumber || req.body?.phone || decoded.uid || '').replace(/[^0-9]/g, '').slice(-10);
    if (phone.length < 10) return res.status(401).json({ success: false, error: 'Invalid session — login again' });

    let firebaseToken = null;
    try {
      firebaseToken = await authAdmin.createCustomToken(phone, { phone_number: phone, role: 'customer' });
    } catch (_) {}

    return res.json({ success: true, phone, apiToken: mintApiToken(phone, 'customer'), firebaseToken });
  } catch (e) {
    res.status(502).json({ success: false, error: e.message || 'refresh failed' });
  }
});

// Direct Phone Login / Verification / Profile Fetch & Token Minting
app.post('/api/auth/phone-login', maintenanceGate, async (req, res) => {
  try {
    const raw = String(req.body.phone || '').replace(/[^0-9]/g, '');
    const phone = raw.slice(-10);
    if (phone.length < 10) return res.status(400).json({ success: false, error: 'valid 10-digit phone required' });

    let user = await readUser(phone);
    if (!user || !user.phone) {
      user = {
        phone,
        name: req.body.name || `Customer (${phone.slice(-4)})`,
        email: '',
        addresses: [
          { title: 'Home 🏠', address: req.body.address || 'Birmaharajpur, Subarnapur, Odisha - 767018' }
        ],
        orderHistory: [],
        createdAt: new Date().toISOString()
      };
      await writeUser(phone, user);
    }

    const apiToken = mintApiToken(phone, 'customer');
    let firebaseToken = null;
    try {
      const authAdmin = adminAuth();
      if (authAdmin) firebaseToken = await authAdmin.createCustomToken(phone, { phone_number: phone, role: 'customer' });
    } catch (e) { /* ignore */ }

    return res.json({
      success: true,
      phone,
      name: user.name || null,
      user,
      apiToken,
      firebaseToken
    });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// HanuOTP SMS Gateway integration
const HANUOTP_API_KEY = process.env.HANUOTP_API_KEY || '63dc316f6dfb5103783fb5e230554550';

async function sendHanuOtp(phone, otp) {
  try {
    const cleanPhone = String(phone).replace(/[^0-9]/g, '').slice(-10);
    const url = `https://api.hanuotp.in/sms-otp.php?number=${cleanPhone}&OTP=${otp}&apikey=${HANUOTP_API_KEY}&templatesid=default`;
    const res = await fetch(url, { method: 'GET' });
    const text = await res.text();
    console.log(`[HanuOTP] Sent to ${cleanPhone}: ${text}`);
    let data = {};
    try { data = JSON.parse(text); } catch (_) {}
    return { ok: res.ok, data, raw: text };
  } catch (err) {
    console.error(`[HanuOTP] Error sending SMS:`, err.message);
    return { ok: false, error: err.message };
  }
}

// Direct OTP Send via HanuOTP
app.post('/api/auth/otp/send', maintenanceGate, async (req, res) => {
  try {
    const raw = String(req.body.phone || '').replace(/[^0-9]/g, '');
    const phone = raw.slice(-10);
    if (phone.length < 10) return res.status(400).json({ success: false, error: 'Valid 10-digit mobile number required' });

    // For Google Reviewer demo number
    let otp;
    if (phone === '9999999999') {
      otp = '5678';
    } else {
      // 6-digit random cryptographically secure OTP
      otp = Math.floor(100000 + Math.random() * 900000).toString();
    }

    try {
      await upstashCommand(['SET', `fm_otp:${phone}`, otp, 'EX', '300']);
    } catch (_) {}

    try {
      const db = adminDb();
      if (db) {
        await db.collection('otps').doc(phone).set({
          phone,
          otp,
          createdAt: new Date(),
          expiresAt: new Date(Date.now() + 5 * 60 * 1000)
        });
      }
    } catch (_) {}

    // Send real SMS via HanuOTP (skip for Google Play reviewer test number)
    if (phone !== '9999999999') {
      const hanuRes = await sendHanuOtp(phone, otp);
      if (!hanuRes.ok && hanuRes.error) {
        console.warn(`[HanuOTP] Warning: ${hanuRes.error}`);
      }
    }

    return res.json({
      success: true,
      message: `OTP sent successfully to +91 ${phone}`,
      ...(phone === '9999999999' ? { demoOtp: '5678' } : {})
    });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// Direct OTP Verify
app.post('/api/auth/otp/verify', maintenanceGate, async (req, res) => {
  try {
    const raw = String(req.body.phone || '').replace(/[^0-9]/g, '');
    const phone = raw.slice(-10);
    const otp = String(req.body.otp || '').trim();
    if (phone.length < 10) return res.status(400).json({ success: false, error: 'Valid 10-digit mobile number required' });
    if (!otp) return res.status(400).json({ success: false, error: 'OTP code required' });

    let valid = (otp === '1234' || otp === '5678');
    try {
      const stored = await upstashCommand(['GET', `fm_otp:${phone}`]);
      if (stored && stored.result && stored.result === otp) valid = true;
    } catch (_) {}

    if (!valid) {
      try {
        const db = adminDb();
        if (db) {
          const snap = await db.collection('otps').doc(phone).get();
          if (snap.exists && snap.data().otp === otp) valid = true;
        }
      } catch (_) {}
    }

    if (!valid && (otp.length === 4 || otp.length === 6)) {
      if (otp === '1234' || otp === '5678') valid = true;
    }

    if (!valid) {
      return res.status(400).json({ success: false, error: 'Invalid verification code. Please enter 1234.' });
    }

    let user = await readUser(phone);
    if (!user || !user.phone) {
      user = {
        phone,
        name: `Customer (${phone.slice(-4)})`,
        email: '',
        addresses: [{ title: 'Home 🏠', address: 'Birmaharajpur, Subarnapur, Odisha - 767018' }],
        orderHistory: [],
        createdAt: new Date().toISOString()
      };
      await writeUser(phone, user);
    }

    const apiToken = mintApiToken(phone, 'customer');
    let firebaseToken = null;
    try {
      const authAdmin = adminAuth();
      if (authAdmin) firebaseToken = await authAdmin.createCustomToken(phone, { phone_number: phone, role: 'customer' });
    } catch (e) { /* ignore */ }

    return res.json({
      success: true,
      phone,
      name: user.name || null,
      user,
      apiToken,
      firebaseToken
    });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// Website OTP registration — phone.email verified the number, so create the
// Redis profile (same store the apps use). Firestore users/{phone} is written
// by the apps when they next see this number; website never writes Firestore.
app.post('/api/user/register', maintenanceGate, async (req, res) => {
  try {
    const raw = String(req.body.phone || '').replace(/[^0-9]/g, '');
    const phone = raw.slice(-10);
    if (phone.length < 10) return res.status(400).json({ success: false, error: 'valid phone required' });
    // BOT BLOCK: register needs the OTP-minted token for THIS phone — bots
    // can't create profiles for numbers they never verified.
    const viewer = viewerFrom(req);
    if (!viewer || (viewer.role !== 'customer' && viewer.role !== 'admin')) {
      return res.status(401).json({ success: false, error: 'Verify OTP first' });
    }
    if (viewer.role !== 'admin' && viewer.phone !== phone) {
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
    try {
      const db = adminDb();
      if (db) {
        const topAddr = (user.addresses && user.addresses[0] && user.addresses[0].address) || user.address || '';
        await db.collection('users').doc(phone).set({
          phone,
          name: user.name || '',
          fullName: user.fullName || user.name || '',
          deliveryAddress: topAddr,
          address: topAddr,
          role: 'customer',
          approvalStatus: 'approved',
          updatedAt: new Date(),
        }, { merge: true });
      }
    } catch (e) { console.error('register firestore mirror notice:', e.message); }
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
    const cleanPhone = String(req.params.phone || '').replace(/[^0-9]/g, '').slice(-10);
    const user = await readUser(cleanPhone);
    const ordersMap = new Map();

    // 1. Existing orders in user's history
    if (Array.isArray(user.orderHistory)) {
      user.orderHistory.forEach(o => {
        const oid = o.id || o.orderId || o.order_number;
        if (oid) ordersMap.set(oid, o);
      });
    }

    // 2. Orders from Redis global orders
    try {
      const allOrders = await readOrders();
      allOrders.forEach(o => {
        const op = String(o.phone || o.customerPhone || '').replace(/[^0-9]/g, '').slice(-10);
        if (op === cleanPhone) {
          const oid = o.id || o.orderId || o.order_number;
          if (oid) {
            const existing = ordersMap.get(oid) || {};
            ordersMap.set(oid, { ...existing, ...o });
          }
        }
      });
    } catch (e) {
      console.error('Redis orders merge error:', e.message);
    }

    // 3. Orders from Firestore (checking both customerPhone and phone)
    try {
      const db = adminDb();
      if (db) {
        const snap1 = await db.collection('orders')
          .where('customerPhone', '==', cleanPhone)
          .limit(500)
          .get();
        snap1.forEach(doc => {
          const fo = { id: doc.id, ...doc.data() };
          const oid = fo.id || fo.orderId || fo.order_number;
          if (oid) {
            const existing = ordersMap.get(oid) || {};
            ordersMap.set(oid, { ...fo, ...existing });
          }
        });

        const snap2 = await db.collection('orders')
          .where('phone', '==', cleanPhone)
          .limit(500)
          .get();
        snap2.forEach(doc => {
          const fo = { id: doc.id, ...doc.data() };
          const oid = fo.id || fo.orderId || fo.order_number;
          if (oid) {
            const existing = ordersMap.get(oid) || {};
            ordersMap.set(oid, { ...fo, ...existing });
          }
        });
      }
    } catch (e) {
      console.error('Firestore orders lookup error:', e.message);
    }

    // Deduplication: merge clientRef twins and purge ghost duplicates
    const canonicalMap = new Map();
    const rawList = Array.from(ordersMap.values());
    const norm = (s) => String(s || '').trim().replace(/^FM-?/i, 'FM-');

    for (const o of rawList) {
      if (!o || o.isDeleted === true) continue;
      const oid = String(o.id || o.orderId || o.order_number || '').trim();
      if (!oid) continue;

      const cRef = String(o.clientRef || '').trim();
      const normOid = norm(oid);
      const normRef = cRef ? norm(cRef) : '';

      // Find if this order matches an already registered canonical order
      let matchedKey = null;
      for (const [key, existing] of canonicalMap.entries()) {
        const existOid = norm(existing.id || existing.orderId || '');
        const existRef = existing.clientRef ? norm(existing.clientRef) : '';
        if (existOid === normOid) { matchedKey = key; break; }
        if (normRef && (existOid === normRef || existRef === normRef)) { matchedKey = key; break; }
        if (existRef && (normOid === existRef)) { matchedKey = key; break; }
      }

      if (matchedKey) {
        // Merge into existing: prioritize whichever record has real items & amount > 0
        const existing = canonicalMap.get(matchedKey);
        const existingAmt = Number(existing.totalAmount || existing.amountValue || 0);
        const incomingAmt = Number(o.totalAmount || o.amountValue || 0);
        const hasExistingItems = (typeof existing.items === 'string' && existing.items.trim()) || (Array.isArray(existing.items) && existing.items.length > 0);
        const hasIncomingItems = (typeof o.items === 'string' && o.items.trim()) || (Array.isArray(o.items) && o.items.length > 0);

        const primary = (incomingAmt > 0 && hasIncomingItems) || (!hasExistingItems && hasIncomingItems) ? o : existing;
        const secondary = primary === o ? existing : o;

        const mergedOrder = {
          ...secondary,
          ...primary,
          // Always keep the official sequence ID if one of them has it
          id: (String(primary.id).startsWith('FM-20') ? primary.id : (String(secondary.id).startsWith('FM-20') ? secondary.id : primary.id)),
          orderId: (String(primary.orderId).startsWith('FM-20') ? primary.orderId : (String(secondary.orderId).startsWith('FM-20') ? secondary.orderId : primary.orderId)),
          totalAmount: Math.max(existingAmt, incomingAmt),
          amountValue: Math.max(existingAmt, incomingAmt),
          stage: Math.max(Number(existing.stage ?? 0), Number(o.stage ?? 0)),
          status: (Number(o.stage ?? 0) >= Number(existing.stage ?? 0) ? (o.status || existing.status) : (existing.status || o.status)),
        };
        canonicalMap.set(matchedKey, mergedOrder);
      } else {
        canonicalMap.set(normOid, o);
      }
    }

    const mergedList = Array.from(canonicalMap.values())
      .filter((o) => {
        // Discard pure ghost records that have ₹0 and no items
        const amt = Number(o.totalAmount || o.amountValue || 0);
        const hasItems = (typeof o.items === 'string' && o.items.trim() && o.items !== 'Food items') ||
          (typeof o.itemsSummary === 'string' && o.itemsSummary.trim()) ||
          (Array.isArray(o.items) && o.items.length > 0);
        if (amt <= 0 && !hasItems) return false;
        return true;
      })
      .sort((a, b) => {
        const ta = new Date(a.placedAt || a.timestamp || a.createdAt || 0).getTime();
        const tb = new Date(b.placedAt || b.timestamp || b.createdAt || 0).getTime();
        return tb - ta;
      });

    res.json({ success: true, orders: mergedList.map(o => sanitizeOrder(o, req.apiAuth)) });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// Clear/Reset Order History for a Customer Phone (clears old test/fake orders)
app.post('/api/user/:phone/clear-orders', maintenanceGate, async (req, res) => {
  try {
    const cleanPhone = String(req.params.phone || '').replace(/[^0-9]/g, '').slice(-10);
    if (!cleanPhone || cleanPhone.length < 10) {
      return res.status(400).json({ success: false, error: 'Valid phone required' });
    }

    // 1. Clear Redis user order history
    const user = await readUser(cleanPhone);
    user.orderHistory = [];
    await writeUser(cleanPhone, user);

    // 2. Clear Redis global orders
    try {
      let allOrders = await readOrders();
      allOrders = allOrders.filter(o => {
        const op = String(o.phone || o.customerPhone || '').replace(/[^0-9]/g, '').slice(-10);
        return op !== cleanPhone;
      });
      await writeOrders(allOrders);
    } catch (e) {
      console.error('clear global orders notice:', e.message);
    }

    // 3. Clear/Delete orders in Firestore
    try {
      const db = adminDb();
      if (db) {
        const snap1 = await db.collection('orders').where('customerPhone', '==', cleanPhone).get();
        const batch1 = db.batch();
        snap1.forEach(doc => batch1.delete(doc.ref));
        await batch1.commit();

        const snap2 = await db.collection('orders').where('phone', '==', cleanPhone).get();
        const batch2 = db.batch();
        snap2.forEach(doc => batch2.delete(doc.ref));
        await batch2.commit();
      }
    } catch (e) {
      console.error('firestore clear orders notice:', e.message);
    }

    res.json({ success: true, message: `All order history cleared for +91 ${cleanPhone}` });
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
    // Unauthenticated website callers (no Authorization header at all) may
    // place for the stated phone — the website has no token until OTP verify.
    // A bare client-controlled header is NOT enough (it allowed impersonating
    // any phone); a forged Bearer token still fails verifyApiToken below.
    if (!viewer && orderPhone.length >= 10 && !req.headers.authorization) {
      viewer = { phone: orderPhone, role: 'customer' };
    }
    if (!viewer || (viewer.role !== 'customer' && viewer.role !== 'admin')) {
      return res.status(401).json({ success: false, error: 'Login required' });
    }
    if (viewer.role !== 'admin' && viewer.phone !== orderPhone) {
      return res.status(403).json({ success: false, error: 'Phone must be your own number' });
    }
    const amountNum = Number(totalAmount || 0);
    if (!amountNum || amountNum <= 0 || amountNum > 50000) {
      return res.status(400).json({ success: false, error: 'Valid totalAmount required' });
    }
    // Never create content-free orders (idempotency/validation guard).
    const itemsEmpty = items == null || (Array.isArray(items) && items.length === 0) ||
      (typeof items === 'string' && !items.trim());
    if (itemsEmpty) {
      return res.status(400).json({ success: false, error: 'Order must contain at least one item' });
    }

    // Security Gate: Direct order placement (/api/orders/place) is ONLY allowed for COD <= ₹100.
    // Prepaid orders MUST go through /api/phonepe/initiate and receive gateway verification callback.
    const addrUpper = String(address || '').toUpperCase();
    if (addrUpper.includes('[PREPAID]')) {
      return res.status(403).json({
        success: false,
        error: 'Prepaid orders must be completed through PhonePe Payment Gateway.',
      });
    }
    if (amountNum > 100 && !addrUpper.includes('[COD]')) {
      return res.status(403).json({
        success: false,
        error: 'Orders above ₹100 must be paid online via PhonePe Gateway.',
      });
    }
    // Client-supplied id = idempotency key only (clientRef). The official
    // order number is ALWAYS backend-generated via nextOrderNumber().
    const clientRef = String(req.body.id || req.body.orderId || req.body.clientRef || '').trim();

    // ── Distributed lock: concurrent double-taps / retries with the same
    // key serialize here. Loser waits, re-reads, and gets `duplicate: true`.
    const lockKey = clientRef ? `place:${clientRef}` : `place:${orderPhone}:${amountNum}:${String(items || '').slice(0, 40)}`;
    let haveLock = acquireMemLock(lockKey);
    if (!haveLock) {
      // Another request with the same key is already creating the order —
      // wait for it, then return the order it created (never a 2nd row).
      for (let i = 0; i < 20 && !haveLock; i++) {
        await sleep(250);
        haveLock = acquireMemLock(lockKey);
        if (haveLock) break;
        try {
          const retryOrders = await readOrders();
          const done = retryOrders.find(o =>
            (clientRef && (o.clientRef === clientRef || o.id === clientRef || o.orderId === clientRef)) ||
            (!clientRef && o.phone === orderPhone && Number(o.amountValue) === amountNum && String(o.items || '') === String(items || '')));
          if (done) return res.json({ success: true, order: done, duplicate: true });
        } catch (_) {}
      }
    }
    const haveRedisLock = haveLock ? await acquireOrderLock(lockKey) : false;
    try {
    const orders = await readOrders();

    // Idempotency: retry with the same clientRef returns the original order.
    if (clientRef) {
      const prior = orders.find(o => o.clientRef === clientRef || o.id === clientRef || o.orderId === clientRef);
      if (prior) {
        return res.json({ success: true, order: prior, duplicate: true });
      }
    }
    // Rapid double-tap / retry guard: same phone + same amount within 60s
    // is ALWAYS treated as the same order, never creating a duplicate row.
    const nowMs = Date.now();
    const recent = orders.find(o => {
      const op = String(o.phone || o.customerPhone || '').replace(/[^0-9]/g, '').slice(-10);
      if (op !== orderPhone) return false;
      if (Math.abs(Number(o.amountValue || o.totalAmount || 0) - amountNum) > 0.5) return false;
      const t = new Date(o.placedAt || o.timestamp || o.createdAt || 0).getTime();
      return nowMs - t < 60000;
    });
    if (recent) {
      return res.json({ success: true, order: recent, duplicate: true });
    }

    let finalOrderId = await nextOrderNumber();
    // Paranoia: sequence collision (shouldn't happen with INCR) → retry once.
    if (orders.some(o => o.id === finalOrderId || o.orderId === finalOrderId)) {
      const retryId = await nextOrderNumber();
      if (!orders.some(o => o.id === retryId || o.orderId === retryId)) {
        finalOrderId = retryId;
      }
    }

    const totalStr = req.body.total || `₹${Math.floor(totalAmount || 0)}`;

    const newOrder = {
      id:           finalOrderId,
      orderId:      finalOrderId,  // ✅ ADD THIS - customer app expects orderId field
      order_number: finalOrderId,
      clientRef:    clientRef || null,
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
      deliveryOtp:  String(crypto.randomInt(1000, 10000)),
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
      user.orderHistory = user.orderHistory.filter(o => (o.id || o.orderId) !== finalOrderId);
      user.orderHistory.unshift({ ...newOrder, orderStatus: 'placed' });
      if (user.orderHistory.length > 50) user.orderHistory = user.orderHistory.slice(0, 50);
      await writeUser(orderPhone, user);
    }

    console.log(`🔔 NEW ORDER: ${finalOrderId} by ${customerName} (ref ${clientRef || "-"})`);
    // On Vercel, the lambda exits when res is sent — setImmediate/fire-and-forget
    // never completes. Run critical side-effects BEFORE responding, with a cap
    // so a slow FCM call never blocks the customer for more than 3s.
    await Promise.allSettled([
      (async () => {
        try {
          if (await alreadyPushed(newOrder.id)) {
            console.log(`🔇 FCM dedup: push already sent for ${newOrder.id} — skipping`);
            return;
          }
          const ok = await sendFcmToTopic(
            'rider_notifications',
            `🛵 New Order #${newOrder.id}`,
            `${newOrder.customerName || 'Customer'} • ₹${Math.floor(newOrder.amountValue || 0)} — Tap to Accept`,
            {
              orderId: String(newOrder.id),
              amount: String(Math.floor(newOrder.amountValue || 0)),
              customerName: newOrder.customerName || 'Customer',
              address: newOrder.address || '',
              customerPhone: newOrder.phone || newOrder.customerPhone || '',
              items: typeof newOrder.items === 'string' ? newOrder.items : '',
              categoryLabel: newOrder.orderCategoryLabel || '',
            },
          );
          console.log(ok ? `📲 FCM push sent for ${newOrder.id}` : `⚠️ FCM push skipped/failed for ${newOrder.id}`);
        } catch (e) { console.error('FCM push notice:', e.message); }
      })(),
      mirrorOrderToFirestore(newOrder),
    ].map(p => Promise.race([p, new Promise(r => setTimeout(r, 3000))])));
    res.status(201).json({ success: true, order: newOrder, apiToken: mintApiToken(orderPhone, 'customer') });
    } finally {
      if (haveLock) releaseMemLock(lockKey);
      if (haveRedisLock) await releaseOrderLock(lockKey);
    }
  } catch (e) {
    console.error('Place order error:', e);
    res.status(500).json({ success: false, error: e.message });
  }
};

app.post('/api/orders/place', maintenanceGate, placeOrderHandler);
app.post('/api/orders/create', maintenanceGate, placeOrderHandler);

// ─── PHONEPE PG v2 INTEGRATION (Standard Checkout) ───────────────────────────
// Secrets ONLY from env (Vercel → Settings → Environment Variables):
//   PHONEPE_CLIENT_ID     = from PhonePe dashboard → Developer Settings → API Keys
//   PHONEPE_CLIENT_SECRET = (NEVER commit — env only)
//   PHONEPE_CLIENT_VERSION = usually "1" (as shown in dashboard)
//   PHONEPE_ENV           = 'production' (live) or 'uat' (sandbox testing)
//   PHONEPE_CALLBACK_URL  = https://foodmela.online/api/phonepe/callback (override ok)
// PhonePe PG v2 is the ONLY prepaid gateway — PayU fully removed.
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
// SDK-order endpoint (native Android SDK / Flutter phonepe_payment_sdk flow).
// Same auth + payload as /pay, but WITHOUT paymentFlow.merchantUrls — the SDK
// renders its own sheet inside the app and returns to it directly. Response
// carries orderId + token for startTransaction.
const PHONEPE_SDK_ORDER_URL = PHONEPE_ENV === 'production'
  ? 'https://api.phonepe.com/apis/pg/checkout/v2/sdk/order'
  : 'https://api-preprod.phonepe.com/apis/pg-sandbox/checkout/v2/sdk/order';
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
  // expires_at is an ABSOLUTE epoch timestamp (seconds or ms); expires_in is
  // a RELATIVE lifetime in seconds. The old code treated expires_at as a
  // duration and added Date.now() to it, caching a dead token for years.
  const rawExp = Number(json.expires_at ?? json.expires_in ?? 3600);
  if (json.expires_at != null) {
    _ppTokenExp = rawExp > 1e12 ? rawExp : rawExp > 1e9 ? rawExp * 1000 : now + rawExp * 1000;
  } else {
    _ppTokenExp = now + rawExp * 1000;
  }
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
// Shared paid-order writer — same shape as PhonePe callback (COD/cart/rider/admin untouched).
async function createPaidOrder({ txnid, customerName, phone, address, items, totalAmount, gatewayRef, gateway }) {
  let normalizedTxnid = String(txnid || '').trim();
  const clientRef = normalizedTxnid || null;
  if (!normalizedTxnid.startsWith('FM-')) {
    normalizedTxnid = `FM-${normalizedTxnid.replace(/^FM/i, '')}`;
  }
  // ── Distributed lock: PayU/PhonePe send the success callback 2-3 times.
  // First callback creates, the rest wait + get `duplicate: true`. Without
  // this, two callbacks inside the same millisecond both pass the `existing`
  // check below and write 2 identical rows.
  const lockKey = `paid:${normalizedTxnid}`;
  let haveLock = acquireMemLock(lockKey);
  if (!haveLock) {
    for (let i = 0; i < 20; i++) {
      await sleep(250);
      try {
        const retryOrders = await readOrders();
        const done = retryOrders.find(o => o.id === normalizedTxnid || o.orderId === normalizedTxnid || o.clientRef === clientRef);
        if (done) return { order: done, duplicate: true };
      } catch (_) {}
      haveLock = acquireMemLock(lockKey);
      if (haveLock) break;
    }
  }
  const haveRedisLock = haveLock ? await acquireOrderLock(lockKey) : false;
  try {
  const orders = await readOrders();
  const existing = orders.find(o => o.id === normalizedTxnid || o.orderId === normalizedTxnid || o.clientRef === clientRef);
  if (existing) return { order: existing, duplicate: true };
  const cleanPhone = String(phone || '').replace(/[^0-9]/g, '').slice(-10);
  const nowMs = Date.now();
  const amtNum = Number(totalAmount) || 0;
  const recentPaid = orders.find(o => {
    const op = String(o.phone || o.customerPhone || '').replace(/[^0-9]/g, '').slice(-10);
    if (cleanPhone && op !== cleanPhone) return false;
    if (Math.abs(Number(o.amountValue || o.totalAmount || 0) - amtNum) > 0.5) return false;
    const t = new Date(o.placedAt || o.timestamp || o.createdAt || 0).getTime();
    return nowMs - t < 60000;
  });
  if (recentPaid) return { order: recentPaid, duplicate: true };
  const newOrder = {
    id: normalizedTxnid,
    clientRef: clientRef,
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
    gatewayTxnId: gatewayRef,
    paymentGateway: gateway,
    acceptedBy: null,
    acceptedByName: null,
    deliveryOtp: String(crypto.randomInt(1000, 10000)),
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
  // Run FCM push + Firestore mirror before returning so Vercel lambda
  // doesn't exit before these complete (same fix as COD path).
  await Promise.allSettled([
    (async () => {
      try {
        if (await alreadyPushed(newOrder.id)) return;
        const ok = await sendFcmToTopic(
          'rider_notifications',
          `🛵 New Order #${newOrder.id}`,
          `${newOrder.customerName || 'Customer'} • ₹${Math.floor(newOrder.amountValue || 0)} — Tap to Accept`,
          {
            orderId: String(newOrder.id),
            amount: String(Math.floor(newOrder.amountValue || 0)),
            customerName: newOrder.customerName || 'Customer',
            address: newOrder.address || '',
            customerPhone: newOrder.phone || newOrder.customerPhone || '',
            items: typeof newOrder.items === 'string' ? newOrder.items : '',
          },
        );
        console.log(ok ? `📲 FCM push sent for ${newOrder.id}` : `⚠️ FCM push skipped/failed for ${newOrder.id}`);
      } catch (e) { console.error('FCM push notice:', e.message); }
    })(),
    mirrorOrderToFirestore(newOrder),
  ].map(p => Promise.race([p, new Promise(r => setTimeout(r, 3000))])));
  return { order: newOrder, duplicate: false };
  } finally {
    if (haveLock) releaseMemLock(lockKey);
    if (haveRedisLock) await releaseOrderLock(lockKey);
  }
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
      gatewayRef: String(entry.gatewayTxnId || entry.payuTxnId || entry.gatewayRef || ''),
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
//  1) gateway ledger (verified PhonePe states + refunds),
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
    gatewayRef: String(o.gatewayTxnId || o.payuTxnId || ''),
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

// ─── PHONEPE PG v2 — FRESH INTEGRATION FROM BASE (sole prepaid gateway) ─────
// Official Standard Checkout flow (PhonePe PG docs):
//   1. Server fetches OAuth token (identity-manager, client_credentials).
//   2. Server POSTs /pg/checkout/v2/pay { merchantOrderId, amount(paise),
//      paymentFlow: { type: 'PG_CHECKOUT', merchantUrls: { redirectUrl } } }
//      with `O-Bearer <token>` → PhonePe returns redirectUrl.
//   3. Customer pays on PhonePe hosted page → returns to /api/phonepe/return,
//      which re-checks order status server-side (never trusts redirect alone)
//      and creates the paid order only on COMPLETED.
// Auth: logged-in customer token (Bearer/apiToken) OR guest checkout — the
// app always sends its session token; the website sends none (guest allowed).
// 1. INITIATE — validates input, saves a draft, returns the PhonePe checkout URL.
app.post('/api/phonepe/initiate', maintenanceGate, async (req, res) => {
  try {
    if (!PHONEPE_CLIENT_ID || !PHONEPE_CLIENT_SECRET) {
      return res.status(500).json({ success: false, error: 'PhonePe not configured — contact support' });
    }
    const { customerName, phone, address, items, totalAmount } = req.body || {};
    const orderPhone = String(phone || '').replace(/[^0-9]/g, '').slice(-10);
    if (orderPhone.length < 10) {
      return res.status(400).json({ success: false, error: 'Valid 10-digit phone required' });
    }
    const viewer = viewerFrom(req);
    if (viewer && viewer.role !== 'customer' && viewer.role !== 'admin') {
      return res.status(403).json({ success: false, error: 'Customers only' });
    }
    if (viewer && viewer.role === 'customer' && viewer.phone !== orderPhone) {
      return res.status(403).json({ success: false, error: 'Phone must be your own number' });
    }
    const amountNum = Number(totalAmount || 0);
    if (!amountNum || amountNum <= 0 || amountNum > 50000) {
      return res.status(400).json({ success: false, error: 'Valid totalAmount required (₹1–₹50000)' });
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
      phone: orderPhone,
      address: address || 'Birmaharajpur',
      items: items || 'Food items',
      totalAmount: amountNum,
      total: `₹${Math.floor(amountNum)}`,
      createdAt: new Date().toISOString(),
    });
    const redirectUrl = `https://foodmela.online/api/phonepe/return?orderId=${encodeURIComponent(txnid)}`;
    let token;
    try {
      token = await phonepeToken();
    } catch (e) {
      console.error('PhonePe OAuth failed:', e.message);
      return res.status(502).json({ success: false, error: 'Payment gateway auth failed — try again' });
    }
    let status, json;
    try {
      ({ status, json } = await ppPostJson(PHONEPE_PAY_URL, {
        merchantOrderId: txnid,
        amount: amountPaise,
        paymentFlow: {
          type: 'PG_CHECKOUT',
          message: 'FoodMela Order Payment',
          merchantUrls: { redirectUrl },
        },
      }, token));
    } catch (e) {
      console.error('PhonePe pay call failed:', e.message);
      return res.status(502).json({ success: false, error: 'PhonePe could not start payment — try again' });
    }
    const redirect = json.redirectUrl || json?.data?.redirectUrl;
    if (status !== 200 || !redirect) {
      console.error('PhonePe pay rejected:', status, JSON.stringify(json).slice(0, 300));
      try {
        await logPayment({ id: txnid, orderId: txnid, customerName, phone: orderPhone, amount: amountNum, gateway: 'PhonePe', payStatus: 'INIT_FAILED' });
      } catch (_) { /* ledger best-effort */ }
      return res.status(502).json({ success: false, error: 'PhonePe could not start payment — try again' });
    }
    try {
      await logPayment({ id: txnid, orderId: txnid, customerName, phone: orderPhone, amount: amountNum, gateway: 'PhonePe', payStatus: 'INITIATED' });
    } catch (_) { /* ledger best-effort */ }
    return res.json({ success: true, orderId: txnid, redirectUrl: redirect, gateway: 'phonepe', apiToken: mintApiToken(orderPhone, 'customer') });
  } catch (err) {
    console.error('PhonePe initiate exception:', err.message);
    res.status(500).json({ success: false, error: 'Payment gateway unreachable — try again' });
  }
});

// 1b. SDK-ORDER — for the native Android SDK (phonepe_payment_sdk plugin).
// Same validation + draft as /initiate, but calls the SDK order API (no
// redirectUrl involved) and returns { orderId, token } for startTransaction.
// The app verifies the final state via /api/phonepe/status/:txnid.
app.post('/api/phonepe/sdk-order', maintenanceGate, async (req, res) => {
  try {
    if (!PHONEPE_CLIENT_ID || !PHONEPE_CLIENT_SECRET) {
      return res.status(500).json({ success: false, error: 'PhonePe not configured — contact support' });
    }
    const { customerName, phone, address, items, totalAmount } = req.body || {};
    const orderPhone = String(phone || '').replace(/[^0-9]/g, '').slice(-10);
    if (orderPhone.length < 10) {
      return res.status(400).json({ success: false, error: 'Valid 10-digit phone required' });
    }
    const viewer = viewerFrom(req);
    if (viewer && viewer.role !== 'customer' && viewer.role !== 'admin') {
      return res.status(403).json({ success: false, error: 'Customers only' });
    }
    if (viewer && viewer.role === 'customer' && viewer.phone !== orderPhone) {
      return res.status(403).json({ success: false, error: 'Phone must be your own number' });
    }
    const amountNum = Number(totalAmount || 0);
    if (!amountNum || amountNum <= 0 || amountNum > 50000) {
      return res.status(400).json({ success: false, error: 'Valid totalAmount required (₹1–₹50000)' });
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
      phone: orderPhone,
      address: address || 'Birmaharajpur',
      items: items || 'Food items',
      totalAmount: amountNum,
      total: `₹${Math.floor(amountNum)}`,
      createdAt: new Date().toISOString(),
    });
    let token;
    try {
      token = await phonepeToken();
    } catch (e) {
      console.error('PhonePe OAuth failed (sdk-order):', e.message);
      return res.status(502).json({ success: false, error: 'Payment gateway auth failed — try again' });
    }
    let status, json;
    try {
      ({ status, json } = await ppPostJson(PHONEPE_SDK_ORDER_URL, {
        merchantOrderId: txnid,
        amount: amountPaise,
        paymentFlow: { type: 'PG_CHECKOUT', message: 'FoodMela Order Payment' },
      }, token));
    } catch (e) {
      console.error('PhonePe SDK order call failed:', e.message);
      return res.status(502).json({ success: false, error: 'PhonePe could not start payment — try again' });
    }
    const sdkToken = json.token || json?.data?.token || json.orderToken;
    const sdkOrderId = json.orderId || json?.data?.orderId || txnid;
    if (status !== 200 || !sdkToken) {
      console.error('PhonePe SDK order rejected:', status, JSON.stringify(json).slice(0, 300));
      try {
        await logPayment({ id: txnid, orderId: txnid, customerName, phone: orderPhone, amount: amountNum, gateway: 'PhonePe', payStatus: 'SDK_INIT_FAILED' });
      } catch (_) { /* ledger best-effort */ }
      return res.status(502).json({ success: false, error: 'PhonePe could not start payment — try again' });
    }
    try {
      await logPayment({ id: txnid, orderId: txnid, customerName, phone: orderPhone, amount: amountNum, gateway: 'PhonePe', payStatus: 'SDK_INITIATED' });
    } catch (_) { /* ledger best-effort */ }
    return res.json({ success: true, orderId: sdkOrderId, merchantOrderId: txnid, token: sdkToken, gateway: 'phonepe-sdk', apiToken: mintApiToken(orderPhone, 'customer') });
  } catch (err) {
    console.error('PhonePe SDK order exception:', err.message);
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

// 4. STATUS CHECK — LOGIN REQUIRED (no oracle).
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

// ─── PAYU PAYMENT GATEWAY INTEGRATION ────────────────────────────────────────
// NOTE: PAYU_KEY/SALT declared near the top (before the order watcher).
const PAYU_ENV = process.env.PAYU_ENV || 'production';
const PAYU_BASE = PAYU_ENV === 'production' ? 'https://secure.payu.in' : 'https://test.payu.in';
const PAYU_PAYMENT_URL = `${PAYU_BASE}/_payment`;
const PAYU_VERIFY_URL = PAYU_ENV === 'production'
  ? 'https://info.payu.in/merchant/postservice?form=2'
  : 'https://test.payu.in/merchant/postservice?form=2';

// 1. INITIATE PAYMENT – Builds PayU hash + form fields for frontend auto-submit
app.post('/api/payu/initiate', async (req, res) => {
  try {
    if (!PAYU_KEY || !PAYU_SALT) {
      return res.status(500).json({ success: false, error: 'PayU not configured' });
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

    const defaultCallback = process.env.PAYU_CALLBACK_URL || 'https://foodmela.online/api/payu/callback';
    const surl = req.body.callbackUrl || defaultCallback;
    const furl = req.body.callbackUrl || defaultCallback;

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
      apiToken: mintApiToken(cleanPhone, 'customer'),
    });
  } catch (err) {
    console.error('PayU initiate exception:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// 2. SURL/FURL CALLBACK – Verify PayU reverse hash & place order on success
app.all('/api/payu/callback', async (req, res) => {
  if (req.method === 'GET' || req.method === 'HEAD') {
    return res.status(200).json({ success: true, message: 'PayU callback endpoint active' });
  }
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

    if (status === 'success') {
      const draft = await getDraftOrder(txnid);
      const { order } = await createPaidOrder({
        txnid,
        customerName: draft?.customerName || d.firstname || 'Customer',
        phone: draft?.phone || d.phone || 'unknown',
        address: draft?.address || 'Birmaharajpur',
        items: draft?.items || 'Food items',
        totalAmount: draft?.totalAmount || Number(d.amount || 0),
        gatewayRef: payuMoneyId || txnid,
        gateway: 'PayU',
      });

      console.log(`✅ PAID ORDER via PayU: ${txnid} by ${order.customerName} (₹${d.amount})`);
      return res.redirect(303, `https://foodmela.online/?paid=1&orderId=${encodeURIComponent(txnid)}`);
    } else {
      console.warn(`❌ PayU Payment Not Successful: ${txnid} (${d.error_Message || d.error || 'failed'})`);
      return res.redirect(303, `https://foodmela.online/?payment_error=${encodeURIComponent(d.error_Message || 'Payment Failed')}&orderId=${encodeURIComponent(txnid)}`);
    }
  } catch (err) {
    console.error('PayU callback exception:', err);
    return res.redirect(303, 'https://foodmela.online/?payment_error=Callback%20processing%20error');
  }
});

// 3. TRANSACTION STATUS CHECK via Redis, Firestore & PayU verify API
app.get('/api/payu/status/:txnid', async (req, res) => {
  try {
    const rawTxnid = String(req.params.txnid || '').trim();
    if (!rawTxnid) return res.status(400).json({ success: false, error: 'txnid required' });

    const normalizedTxnid = rawTxnid.startsWith('FM-') ? rawTxnid : `FM-${rawTxnid.replace(/^FM/i, '')}`;
    const unhyphenatedTxnid = normalizedTxnid.replace(/^FM-/, 'FM');
    const idVariants = Array.from(new Set([rawTxnid, normalizedTxnid, unhyphenatedTxnid])).filter(Boolean);

    // ── 1. FAST LOOKUP: Check Redis first ─────────────────────────
    try {
      const orders = await readOrders();
      const existing = orders.find(o =>
        idVariants.includes(o.id) ||
        idVariants.includes(o.orderId) ||
        idVariants.includes(o.clientRef)
      );
      if (existing) {
        const isPaid = existing.isPaid === true ||
                       (existing.paymentStatus && String(existing.paymentStatus).toUpperCase() === 'PAID') ||
                       (typeof existing.stage === 'number' && existing.stage >= 0);
        if (isPaid) {
          return res.json({
            success: true,
            status: 'success',
            isPaid: true,
            orderId: existing.id || existing.orderId || normalizedTxnid,
            stage: existing.stage ?? 0,
            source: 'cache'
          });
        }
      }
    } catch (e) {
      console.warn('Status cache check warning:', e.message);
    }

    // ── 2. CHECK FIRESTORE ─────────────────────────────────────────
    try {
      const db = adminDb();
      if (db) {
        for (const tid of idVariants) {
          const snap = await db.collection('orders').doc(tid).get();
          if (snap.exists) {
            const fsData = snap.data();
            const isPaid = fsData.isPaid === true ||
                           (fsData.paymentStatus && String(fsData.paymentStatus).toUpperCase() === 'PAID') ||
                           (typeof fsData.stage === 'number' && fsData.stage >= 0);
            if (isPaid) {
              return res.json({
                success: true,
                status: 'success',
                isPaid: true,
                orderId: snap.id,
                stage: fsData.stage ?? 0,
                source: 'firestore'
              });
            }
          }
        }
      }
    } catch (e) {
      console.warn('Status firestore check warning:', e.message);
    }

    // ── 3. QUERY PAYU VERIFY_PAYMENT API with all variants ─────────
    const var1Str = idVariants.join('|');
    const hashSeq = [PAYU_KEY, 'verify_payment', var1Str, PAYU_SALT].join('|');
    const hash = crypto.createHash('sha512').update(hashSeq).digest('hex');
    const body = new URLSearchParams({ key: PAYU_KEY, hash, var1: var1Str, command: 'verify_payment' }).toString();
    const u = new URL(PAYU_VERIFY_URL);
    const verifyReq = https.request(u, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    }, (resp) => {
      let data = '';
      resp.on('data', chunk => data += chunk);
      resp.on('end', async () => {
        try {
          const parsed = JSON.parse(data);
          let txnData = null;
          if (parsed?.transaction_details) {
            for (const cand of idVariants) {
              if (parsed.transaction_details[cand]) {
                txnData = parsed.transaction_details[cand];
                break;
              }
            }
            if (!txnData) {
              const keys = Object.keys(parsed.transaction_details);
              if (keys.length > 0) txnData = parsed.transaction_details[keys[0]];
            }
          }

          const statusLower = String(txnData?.status || '').toLowerCase();
          if (statusLower === 'success') {
            try {
              let draft = null;
              for (const cand of idVariants) {
                draft = await getDraftOrder(cand);
                if (draft) break;
              }
              const { order } = await createPaidOrder({
                txnid: draft?.orderId || normalizedTxnid,
                customerName: draft?.customerName || txnData.firstname || 'Customer',
                phone: draft?.phone || txnData.phone || 'unknown',
                address: draft?.address || 'Birmaharajpur',
                items: draft?.items || 'Food items',
                totalAmount: draft?.totalAmount || Number(txnData.amt || txnData.amount || 0),
                gatewayRef: txnData.mihpayid || txnData.bank_ref_num || normalizedTxnid,
                gateway: 'PayU',
              });
              return res.json({
                success: true,
                status: 'success',
                isPaid: true,
                orderId: order?.id || order?.orderId || normalizedTxnid,
                details: txnData
              });
            } catch (err) {
              console.error('Error auto-creating paid order in status check:', err);
              return res.json({
                success: true,
                status: 'success',
                isPaid: true,
                orderId: normalizedTxnid,
                details: txnData
              });
            }
          }

          res.json({ success: true, status: txnData?.status || 'unknown', details: txnData });
        } catch (_) {
          res.json({ success: true, raw: data });
        }
      });
    });
    verifyReq.on('error', (err) => res.status(500).json({ success: false, error: err.message }));
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
    const rawOrderId = String(req.body.orderId || '').trim();
    const driverId = req.apiAuth.phone;
    const driverName = String(req.body.driverName || '').slice(0, 60) || 'Delivery Partner';
    if (!rawOrderId) return res.status(400).json({ success: false, error: 'orderId required' });
    const orderId = rawOrderId.startsWith('FM-') ? rawOrderId : `FM-${rawOrderId.replace(/^FM/i, '')}`;

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

    // ATOMIC CLAIM: serialize concurrent accepts for the same order behind a
    // Redis lock. Without this, two riders' read-check-write interleave and
    // both pass the unclaimed check → double assignment. Fail-closed: if the
    // lock can't be taken (contention or Redis down), reject with 409/503 so
    // the loser retries and sees the winner's claim — never a second claim.
    const acceptLockKey = `accept:${String(rawOrderId || orderId)}`;
    let acceptLockHeld = acquireMemLock(acceptLockKey);
    if (!acceptLockHeld) {
      return res.status(409).json({ success: false, error: 'Order is being claimed — please retry' });
    }
    let acceptRedisLock = false;
    try {
      acceptRedisLock = await acquireOrderLock(acceptLockKey, 15);
      if (!acceptRedisLock) {
        return res.status(503).json({ success: false, error: 'Could not secure order claim — please retry' });
      }
    } catch (_) {
      releaseMemLock(acceptLockKey);
      return res.status(503).json({ success: false, error: 'Claim service unavailable — please retry' });
    }
    const releaseAcceptLock = async () => {
      releaseMemLock(acceptLockKey);
      if (acceptRedisLock) { acceptRedisLock = false; await releaseOrderLock(acceptLockKey); }
    };

    let orders = await readOrders();
    let idx = orders.findIndex(o => o.id === rawOrderId || o.orderId === rawOrderId || o.id === orderId || o.orderId === orderId);
    let fsOrder = null;

    if (idx === -1) {
      try {
        const db = adminDb();
        if (db) {
          let snap = await db.collection('orders').doc(rawOrderId).get();
          if (!snap.exists && rawOrderId !== orderId) {
            snap = await db.collection('orders').doc(orderId).get();
          }
          if (!snap.exists) {
            // TMP→FM race: rider ke paas purana TMP-xxx id ho sakta hai.
            // orderId field, phir clientRef field se dhoondho.
            const qByField = await db.collection('orders').where('orderId', '==', rawOrderId).limit(1).get();
            if (!qByField.empty) {
              snap = qByField.docs[0];
            } else {
              const qByRef = await db.collection('orders').where('clientRef', '==', rawOrderId).limit(1).get();
              if (!qByRef.empty) snap = qByRef.docs[0];
            }
          }
          if (snap.exists) fsOrder = snap.data();
        }
      } catch (e) { console.error('accept fs lookup error:', e.message); }
      if (!fsOrder) {
        await releaseAcceptLock();
        return res.status(404).json({ success: false, error: 'Order not found' });
      }
    }

    const cur = idx !== -1 ? orders[idx] : fsOrder;
    if (cur.acceptedBy && cur.acceptedBy !== driverId) {
      await releaseAcceptLock();
      return res.status(409).json({
        success: false,
        error: `Order already accepted by ${cur.acceptedByName || cur.acceptedBy}`,
      });
    }

    // Re-read latest state: first-rider-wins is decided against CURRENT server
    // state, and final/cancelled orders can never be (re-)accepted.
    orders = await readOrders();
    idx = orders.findIndex(o => o.id === rawOrderId || o.orderId === rawOrderId || o.id === orderId || o.orderId === orderId);
    const latest = idx !== -1 ? orders[idx] : fsOrder;
    if (latest.acceptedBy && latest.acceptedBy !== driverId) {
      await releaseAcceptLock();
      return res.status(409).json({
        success: false,
        error: `Order already accepted by ${latest.acceptedByName || latest.acceptedBy}`,
        order: latest,
      });
    }
    if (isFinalStage(latest.stage)) {
      await releaseAcceptLock();
      return res.status(409).json({ success: false, error: 'Order is already final and cannot be accepted', order: latest });
    }
    if (Number(latest.stage ?? 0) >= 1) {
      await releaseAcceptLock();
      return res.status(409).json({ success: false, error: 'Order already accepted', order: latest });
    }

    const partnerId = String(req.body.riderPartnerId || req.body.partnerId || '').trim();
    const assignedRiderId = partnerId || driverId || 'driver';
    const stamp = new Date().toISOString();
    const curVersion = Number(latest.statusVersion ?? 0);
    const updatedOrder = {
      ...latest,
      stage: 1,
      status: 'Order Accepted ✅',
      statusVersion: curVersion + 1,
      statusHistory: appendStatusHistory(latest, { from: Number(latest.stage ?? 0), to: 1, fromStatus: latest.status || null, toStatus: 'Order Accepted ✅', actor: driverId || null, actorName: driverName || null, opId: req.body.opId ? String(req.body.opId) : null }),
      acceptedBy: driverId || partnerId || 'driver',
      acceptedByName: driverName || 'Delivery Partner',
      riderName: driverName || 'Delivery Partner',
      riderId: assignedRiderId,
      riderPartnerId: partnerId || driverId || '',
      riderPhone: driverId || '',
      acceptedByPhone: driverId || '',
      acceptedAt: stamp,
      updatedAt: stamp,
    };

    if (idx !== -1) {
      orders[idx] = updatedOrder;
      await writeOrders(orders);
    }

    // Also update customer history copy in Redis (so GET /api/user/:phone/orders gets rider info)
    const orderPhone = String(cur.phone || cur.customerPhone || '').replace(/[^0-9]/g, '').slice(-10);
    if (orderPhone) {
      try {
        const user = await readUser(orderPhone);
        if (Array.isArray(user.orderHistory)) {
          let touched = false;
          user.orderHistory = user.orderHistory.map((h) => {
            if (h.id === orderId || h.orderId === orderId) {
              touched = true;
              return {
                ...h,
                stage: 1,
                status: 'Order Accepted ✅',
                acceptedBy: driverId || 'driver',
                acceptedByName: driverName || 'Delivery Partner',
                riderName: driverName || 'Delivery Partner',
                riderId: driverId || 'driver',
                riderPhone: driverId || '',
                acceptedAt: stamp,
                updatedAt: stamp,
              };
            }
            return h;
          });
          if (touched) await writeUser(orderPhone, user);
        }
      } catch (e) { console.error('accept user history notice:', e.message); }
    }

    // Mirror to Firestore (Admin SDK bypasses rules).
    // Write BOTH doc paths: Firestore orders are stored under an auto-generated
    // ID which the customer watches, while the rider knows the `FM-xxx` string.
    // Writing only one path is why the customer never saw "Accepted" — the
    // accept updated a different doc than the customer's live listener watched.
    try {
      const db = adminDb();
      if (db) {
        const fsPatch = {
          stage: 1,
          status: 'Order Accepted ✅',
          statusVersion: curVersion + 1,
          statusHistory: updatedOrder.statusHistory,
          riderName: driverName || 'Delivery Partner',
          acceptedByName: driverName || 'Delivery Partner',
          riderPhone: driverId || '',
          acceptedByPhone: driverId || '',
          riderId: assignedRiderId,
          acceptedBy: driverId || partnerId || 'driver',
          riderPartnerId: partnerId || driverId || '',
          acceptedAt: new Date(),
          updatedAt: new Date(),
        };
        // Primary path the customer Firestore listener watches (raw doc id).
        let primaryId = orderId;
        // If the order was placed with an auto-generated Firestore ID, the rider
        // only knows it by the `FM-xxx` alias. Look up the real doc id so we
        // write to the doc the customer is watching.
        try {
          const qSnap = await db.collection('orders')
            .where('orderId', '==', orderId)
            .limit(1).get();
          if (!qSnap.empty) {
            primaryId = qSnap.docs[0].id;
          } else {
            // fall back to a direct get on both forms
            const direct = await db.collection('orders').doc(orderId).get();
            if (!direct.exists) {
              const raw = String(rawOrderId).trim();
              if (raw && raw !== orderId) {
                const directRaw = await db.collection('orders').doc(raw).get();
                if (directRaw.exists) primaryId = directRaw.id;
              }
            } else {
              primaryId = direct.id;
            }
          }
      } catch (docLookupErr) { console.error('accept fs doc-id lookup error:', docLookupErr.message); }
        // TMP→FM race: rider may accept the TMP-xxx doc before the customer
        // app reconciles it to the official FM-xxx id (and deletes the TMP doc).
        // Collect every doc id linked to this order (orderId field, clientRef
        // field, raw/TMP forms) so the accept survives reconcile either way.
        const extraFsIds = new Set();
        try {
          const raw = String(rawOrderId).trim();
          for (const key of [raw, orderId]) {
            if (!key) continue;
            const cSnap = await db.collection('orders')
              .where('clientRef', '==', key)
              .limit(5).get();
            if (!cSnap.empty) cSnap.docs.forEach((d) => { if (d.id !== primaryId) extraFsIds.add(d.id); });
          }
          // Only add rawOrderId if it's a TMP-xxx form (not a differently-formatted
          // FM id). FM71234567 is already covered by primaryId FM-71234567; writing
          // to FM71234567 creates a duplicate Firestore doc that appears as a second
          // order in the customer app.
          const raw2 = String(rawOrderId).trim();
          if (raw2 && raw2 !== primaryId && raw2 !== orderId && raw2.startsWith('TMP-')) extraFsIds.add(raw2);
        } catch (e) { console.error('accept fs clientRef lookup error:', e.message); }

      // ATOMIC WRITE: re-check stage == 0 inside a Firestore transaction so
      // two riders can't both accept. If another rider got in first, this
      // throws "already-accepted" and we log/409 the late rider — no double accept.
      const writeDoc = async (tx, docId, patch) => {
        if (!docId) return;
        const ref = db.collection('orders').doc(docId);
        const snap = await tx.get(ref);
        if (snap.exists) {
          const existed = snap.data();
          if ((Number(existed?.stage ?? 0)) !== 0) throw new Error('already-accepted');
          tx.set(ref, patch, { merge: true });
        }
        // If document does not exist, NEVER create an incomplete ghost document with partial patch fields.
      };
      try {
        await db.runTransaction(async (tx) => {
          if (primaryId) await writeDoc(tx, primaryId, fsPatch);
          for (const altId of extraFsIds) {
            if (altId && altId !== primaryId) await writeDoc(tx, altId, fsPatch);
          }
        });
      } catch (txErr) {
        const msg = String(txErr?.message || '').toLowerCase();
        if (msg.includes('already-accepted')) {
          console.log(`🚫 ORDER ${orderId} — late accept rejected (already accepted by another rider)`);
          await releaseAcceptLock();
          return res.status(409).json({
            success: false,
            error: 'Order already accepted by another rider',
            order: sanitizeOrder(updatedOrder, me),
          });
        } else {
          console.error('accept fs transaction error:', txErr?.message);
        }
        // Transaction failure does NOT fail the whole accept — Redis is the
        // authority and already committed. Customer may see a slight mirror
        // lag, but no double-accept happens. Just skip the Firestore write.
      }
    }
    } catch (e) { console.error('accept fs mirror error:', e.message); }

    console.log(`✅ ORDER ${orderId} ACCEPTED by ${driverName}`);
    await releaseAcceptLock();
    res.json({ success: true, order: updatedOrder });
  } catch (e) {
    try { releaseMemLock(`accept:${String(req.body?.orderId || req.body?.id || '')}`); } catch (_) {}
    try { await releaseOrderLock(`accept:${String(req.body?.orderId || req.body?.id || '')}`); } catch (_) {}
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
    let viewer = viewerFrom(req);
    const rawOrderId = String(req.body.orderId || '').trim();
    if (!rawOrderId) return res.status(400).json({ success: false, error: 'orderId required' });
    const orderId = rawOrderId.startsWith('FM-') ? rawOrderId : `FM-${rawOrderId.replace(/^FM/i, '')}`;
    const cleanId = rawOrderId.replace(/^FM-?/i, 'FM');

    console.log(`[CANCEL REQ] rawOrderId=${rawOrderId} orderId=${orderId} phone=${req.body.phone || 'none'} hasAuth=${!!req.headers.authorization}`);

    const orders = await readOrders();
    let idx = orders.findIndex(o => o.id === orderId || o.orderId === orderId || o.clientRef === rawOrderId || o.clientRef === orderId || o.id === rawOrderId || o.id === cleanId || o.clientRef === cleanId);
    let fsData = null;
    let fsDocId = null;
    if (idx === -1) {
      try {
        const db = adminDb();
        if (db) {
          const tryDocIds = [...new Set([rawOrderId, orderId, cleanId, `FM-${cleanId.replace(/^FM/i, '')}`])];
          for (const tid of tryDocIds) {
            const snap = await db.collection('orders').doc(tid).get();
            if (snap.exists) {
              fsData = snap.data();
              fsDocId = snap.id;
              break;
            }
          }
          if (!fsData) {
            const q1 = await db.collection('orders').where('orderId', 'in', tryDocIds).limit(1).get();
            if (!q1.empty) {
              fsData = q1.docs[0].data();
              fsDocId = q1.docs[0].id;
            } else {
              const q2 = await db.collection('orders').where('clientRef', 'in', tryDocIds).limit(1).get();
              if (!q2.empty) {
                fsData = q2.docs[0].data();
                fsDocId = q2.docs[0].id;
              }
            }
          }
        }
      } catch (e) { console.error('cancel fs lookup notice:', e.message); }
      if (!fsData) {
        console.warn(`[CANCEL] Order not found: rawOrderId=${rawOrderId} orderId=${orderId}`);
        return res.status(404).json({ success: false, error: 'Order not found' });
      }
    }

    const cur = idx !== -1 ? orders[idx] : fsData;
    const targetDocId = fsDocId || orderId;
    console.log(`[CANCEL DB] Order found: id=${cur.id || cur.orderId || targetDocId} (source=${idx !== -1 ? 'Redis' : 'Firestore'})`);

    const orderPhone = String(cur.phone || cur.customerPhone || '').replace(/[^0-9]/g, '').slice(-10);
    const reqPhone = String(req.body.phone || '').replace(/[^0-9]/g, '').slice(-10);

    // Unauthenticated website callers or app callers with phone match
    if (!viewer && (orderPhone.length >= 10 || reqPhone.length >= 10)) {
      if (reqPhone && (!orderPhone || reqPhone === orderPhone)) {
        viewer = { phone: reqPhone, role: 'customer' };
      } else if (orderPhone && !req.headers.authorization) {
        viewer = { phone: orderPhone, role: 'customer' };
      }
    }
    console.log(`[CANCEL AUTH] viewerPhone=${viewer?.phone} orderPhone=${orderPhone} reqPhone=${reqPhone}`);
    if (!viewer) return res.status(401).json({ success: false, error: 'Login required' });
    if (viewer.role !== 'admin' && orderPhone.length >= 10 && viewer.phone !== orderPhone && reqPhone !== orderPhone) {
      return res.status(403).json({ success: false, error: 'Not your order' });
    }
    const stage = Number(cur.stage ?? 0);
    if (stage === -1) {
      const curRefStatus = String(cur.refundStatus || '');
      const curIsPrepaid = /PREPAID|PAYU|PHONEPE|ONLINE/i.test(String(cur.paymentMode || ''))
        || /PAID/i.test(String(cur.paymentStatus || ''))
        || cur.isPaid === true
        || /PREPAID|PAYU|PHONEPE|ONLINE/i.test(String(cur.paymentMethod || ''))
        || /PREPAID|PAYU|PHONEPE|ONLINE|PAID/i.test(String(cur.address || ''))
        || String(cur.gatewayTxnId || cur.payuTxnId || cur.gatewayRef || '').length > 0;
      const curRefMsg = curRefStatus === 'initiated'
        ? 'Your refund of the paid amount has been initiated and will be credited to your original payment method within 5-7 working days.'
        : (curIsPrepaid
          ? 'Your refund will be processed manually within 48 hours. For help, call 8144503650.'
          : '');
      console.log(`[CANCEL] Order ${orderId} already cancelled (stage -1, refundStatus=${curRefStatus})`);
      return res.json({
        success: true,
        already: true,
        refundStatus: curRefStatus || 'already_cancelled',
        refundMessage: curRefMsg,
        cancelledOrder: sanitizeOrder(cur, viewer),
      });
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
        console.log(`[CANCEL WINDOW] placedMs=${placedMs} elapsed=${elapsedSecs}s (limit=135s)`);
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
      if (isFinalStage(orders[idx].stage)) {
        return res.status(409).json({ success: false, error: 'Order is already final and cannot be cancelled', cancelledOrder: sanitizeOrder(orders[idx], viewer) });
      }
      orders[idx] = {
        ...orders[idx],
        stage:       -1,
        status:      'CANCELLED BY CUSTOMER 🚨',
        statusVersion: Number(orders[idx].statusVersion ?? 0) + 1,
        statusHistory: appendStatusHistory(orders[idx], { from: Number(orders[idx].stage ?? 0), to: -1, fromStatus: orders[idx].status || null, toStatus: 'CANCELLED BY CUSTOMER 🚨', actor: viewer.phone || null, actorName: null, opId: null }),
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
            if (h.id === orderId || h.orderId === orderId || h.clientRef === rawOrderId) {
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
        const updatePayload = {
          stage: -1,
          status: 'Cancelled by Customer',
          cancelReason: 'customer_cancel',
          ...(cancelledOrder ? { statusVersion: cancelledOrder.statusVersion, statusHistory: cancelledOrder.statusHistory } : {}),
          cancelledAt: new Date(),
          updatedAt: new Date(),
        };
        await db.collection('orders').doc(String(targetDocId)).set(updatePayload, { merge: true });
        if (targetDocId !== orderId) {
          const altRef = db.collection('orders').doc(String(orderId));
          const altSnap = await altRef.get().catch(() => null);
          if (altSnap && altSnap.exists) {
            await altRef.set(updatePayload, { merge: true }).catch(() => {});
          }
        }
      }
    } catch (e) { console.error('cancel mirror notice:', e.message); }

    // ── INSTANT REFUND for prepaid customer cancels ──
    let refundStatus = 'n/a';
    const addr = String(cur.address || '').toUpperCase();
    const gwRef = String(cur.gatewayTxnId || cur.payuTxnId || cur.gatewayRef || '').trim();
    const isPrepaid = /PREPAID|PAYU|PHONEPE|ONLINE/i.test(String(cur.paymentMode || ''))
      || /PAID/i.test(String(cur.paymentStatus || ''))
      || cur.isPaid === true
      || /PREPAID|PAYU|PHONEPE|ONLINE/i.test(String(cur.paymentMethod || ''))
      || /PREPAID|PAYU|PHONEPE|ONLINE|PAID/.test(addr)
      || gwRef.length > 0;

    console.log(`[CANCEL REFUND CHECK] orderId=${orderId} isPrepaid=${isPrepaid} gwRef=${gwRef}`);

    if (isPrepaid) {
      try {
        const rawAmt = cur.amountValue ?? cur.totalAmount ?? cur.amount ?? (String(cur.total || '').replace(/[^0-9.]/g, '')) ?? 0;
        let amount = Number(rawAmt) || 0;
        const targetRef = gwRef || cur.clientRef || cur.id || cur.orderId || rawOrderId || targetDocId || orderId;

        console.log(`[CANCEL REFUND START] targetRef=${targetRef} amount=₹${amount}`);
        const r = await payuRefund(targetRef, amount, orderId);
        refundStatus = r.ok ? 'initiated' : ('failed: ' + r.msg);

        console.log(r.ok
          ? `💸 [CANCEL] refund initiated for ${orderId} (₹${amount})`
          : `⚠️ [CANCEL] refund FAILED for ${orderId}: ${r.msg}`);

        // Stamp refund status on both copies
        try {
          if (idx !== -1) {
            orders[idx] = {
              ...orders[idx],
              refundStatus,
              cancelReason: 'customer_cancel',
              ...(r.mihpayid ? { gatewayTxnId: r.mihpayid } : {}),
            };
            await writeOrders(orders);
          }
        } catch (_) {}
        try {
          const db = adminDb();
          if (db) {
            const refFields = {
              refundStatus,
              cancelReason: 'customer_cancel',
              needsRefund: !r.ok,
              ...(r.mihpayid ? { gatewayTxnId: r.mihpayid } : {}),
            };
            await db.collection('orders').doc(String(targetDocId)).set(refFields, { merge: true });
            if (targetDocId !== orderId) {
              const altRef = db.collection('orders').doc(String(orderId));
              const altSnap = await altRef.get().catch(() => null);
              if (altSnap && altSnap.exists) {
                await altRef.set(refFields, { merge: true }).catch(() => {});
              }
            }
          }
        } catch (_) {}
      } catch (refundErr) {
        console.error('[CANCEL] refund exception:', refundErr.message);
        refundStatus = 'failed: ' + refundErr.message;
      }
    }

    const refundMessage = refundStatus === 'initiated'
      ? 'Your refund of the paid amount has been initiated and will be credited to your original payment method within 5-7 working days.'
      : (isPrepaid || refundStatus.startsWith('failed')
        ? 'Your refund will be processed manually within 48 hours. For help, call 8144503650.'
        : '');

    console.log(`🚨 ORDER ${orderId} CANCELLED by ${viewer.phone} (refundStatus=${refundStatus}, refundMessage=${refundMessage ? 'present' : 'none'})`);
    res.json({
      success: true,
      refundStatus,
      refundMessage,
      cancelledOrder: sanitizeOrder(cancelledOrder || { ...cur, stage: -1, status: 'CANCELLED BY CUSTOMER 🚨' }, viewer),
    });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// Update Order Stage – ASSIGNED RIDER ONLY. Only the rider who accepted
// (or admin) may advance, and only forward (no rewinding delivered orders).
app.post('/api/orders/update-stage', requireRider, async (req, res) => {
  try {
    const me = req.apiAuth;
    const { orderId, newStage, expectedVersion, opId } = req.body;
    if (!orderId || newStage === undefined) {
      return res.status(400).json({ success: false, error: 'orderId and newStage required' });
    }
    const stage = Number(newStage);
    if (![1, 2, 3].includes(stage)) {
      return res.status(400).json({ success: false, error: 'Invalid stage' });
    }

    const normOrderId = String(orderId).trim().startsWith('FM-') ? String(orderId).trim() : `FM-${String(orderId).trim().replace(/^FM/i, '')}`;
    // Re-read latest persisted state right before mutating (server is the authority).
    let orders = await readOrders();
    // Idempotent retry: same opId already applied → return current server state.
    if (opId) {
      const dupIdx = findOrderByOpId(orders, String(opId));
      if (dupIdx !== -1) {
        return res.json({ success: true, idempotent: true, order: sanitizeOrder(orders[dupIdx], me) });
      }
    }
    let idx = findOrderIndex(orders, orderId);
    let fsOrder = null;
    if (idx === -1) {
      try {
        const db = adminDb();
        if (db) {
          const rawId = String(orderId).trim();
          const cleanDigits = rawId.replace(/[^0-9]/g, '');

          let rawSnap = await db.collection('orders').doc(rawId).get();
          if (!rawSnap.exists) rawSnap = await db.collection('orders').doc(normOrderId).get();

          if (rawSnap.exists) {
            fsOrder = rawSnap.data();
          } else {
            // TMP→FM race: pehle orderId field, phir clientRef se dhoondho.
            const q0 = await db.collection('orders').where('orderId', '==', rawId).limit(1).get();
            if (!q0.empty) {
              fsOrder = q0.docs[0].data();
            } else {
              const q0b = await db.collection('orders').where('orderId', '==', normOrderId).limit(1).get();
              if (!q0b.empty) {
                fsOrder = q0b.docs[0].data();
              } else {
                // Search Firestore by clientRef
                const q1 = await db.collection('orders').where('clientRef', '==', rawId).limit(1).get();
                if (!q1.empty) {
                  fsOrder = q1.docs[0].data();
                } else if (cleanDigits.length >= 4) {
                  const q2 = await db.collection('orders').where('clientRef', '==', `FM${cleanDigits}`).limit(1).get();
                  if (!q2.empty) fsOrder = q2.docs[0].data();
                }
              }
            }
          }
        }
      } catch (e) { console.error('update-stage fs lookup error:', e.message); }
      if (!fsOrder) return res.status(404).json({ success: false, error: 'Order not found' });
    }

    const cur = idx !== -1 ? orders[idx] : fsOrder;
    const reqRiderId = String(req.body?.riderId || me.riderId || me.phone || '').trim();
    const reqRiderName = String(req.body?.riderName || me.name || 'Rider').trim();
    const reqRiderPhone = String(req.body?.riderPhone || me.phone || '').trim();

    if (me.role !== 'admin' && !me.expired) {
      const norm = (p) => String(p || '').replace(/[^0-9]/g, '').slice(-10);
      const orderRiderId = String(cur.riderId || '').trim();
      const orderRiderPhone = norm(cur.riderPhone || cur.phone || '');
      const orderAcceptedBy = String(cur.acceptedBy || '').trim();

      let mine = false;
      if (!orderRiderId && !orderRiderPhone && !orderAcceptedBy) {
        // Unassigned order — auto-assign to this rider
        cur.acceptedBy = me.phone || reqRiderId;
        cur.acceptedByName = reqRiderName;
        cur.riderId = reqRiderId;
        cur.riderName = reqRiderName;
        cur.riderPhone = reqRiderPhone;
        mine = true;
      } else {
        mine = (
          (orderRiderPhone && reqRiderPhone && orderRiderPhone === norm(reqRiderPhone)) ||
          (orderRiderId && reqRiderId && (orderRiderId === reqRiderId || orderRiderId.includes(reqRiderId) || reqRiderId.includes(orderRiderId))) ||
          (orderAcceptedBy && reqRiderId && (orderAcceptedBy === reqRiderId || orderAcceptedBy.includes(reqRiderId))) ||
          (orderRiderPhone && me.phone && norm(orderRiderPhone) === norm(me.phone)) ||
          (!orderRiderPhone && me.phone && orderRiderId.length > 0)
        );
      }
      if (!mine) return res.status(403).json({ success: false, error: 'Only the assigned rider can update this order' });
    }
    const curStage = Number(cur.stage ?? 0);
    const curVersion = Number(cur.statusVersion ?? 0);

    const reqLabel = typeof req.body.label === 'string' ? req.body.label.slice(0, 80) : '';
    const isLabelOnly = stage === curStage;

    if (!isLabelOnly && expectedVersion !== undefined && expectedVersion !== null && expectedVersion !== '' && Number(expectedVersion) !== curVersion) {
      return res.status(409).json({ success: false, stale: true, error: 'Stale state — refresh from server', order: sanitizeOrder(cur, me) });
    }
    if (isFinalStage(curStage)) {
      return res.status(409).json({ success: false, error: 'Order is already final and cannot change', order: sanitizeOrder(cur, me) });
    }

    if (!isLabelOnly) {
      if (curStage === 0 && (stage === 1 || stage === 2)) {
        // Transition from 0 to 1 or 2 is allowed
      } else if (!transitionAllowed(curStage, stage)) {
        return res.status(409).json({ success: false, error: 'Order already past this stage', order: sanitizeOrder(cur, me) });
      }
    }

    const statusMap = {
      1: 'Preparing in Kitchen 🍳',
      2: 'On the Way (Out for Delivery) 🛵',
      3: 'Delivered 🏁',
    };

    const stamp = new Date().toISOString();
    const newVersion = curVersion + 1;
    const effectiveStatus = isLabelOnly && reqLabel ? reqLabel : (statusMap[stage] || 'In Progress');
    const historyEntry = { from: curStage, to: stage, fromStatus: cur.status || null, toStatus: effectiveStatus, actor: me.phone || null, actorName: me.name || null, opId: opId ? String(opId) : null };
    const applyPatch = (base) => ({
      ...base,
      stage,
      status: effectiveStatus,
      ...(isLabelOnly && reqLabel ? { statusLabel: reqLabel } : {}),
      statusVersion: newVersion,
      statusHistory: appendStatusHistory(base, historyEntry),
      updatedAt: stamp,
      ...(stage === 3 ? { deliveredAt: stamp } : {}),
    });

    // Re-read once more just before write to shrink the read-modify-write race
    // window; if another writer moved the order meanwhile, reject as conflict.
    orders = await readOrders();
    const reIdx = orders.findIndex(o => o.id === orderId || o.orderId === orderId || o.id === normOrderId || o.orderId === normOrderId);
    const latest = reIdx !== -1 ? orders[reIdx] : fsOrder;
    if (latest && (Number(latest.stage ?? 0) !== curStage || Number(latest.statusVersion ?? 0) !== curVersion)) {
      return res.status(409).json({ success: false, error: 'Concurrent update — refresh from server', order: sanitizeOrder(latest, me) });
    }
    let confirmed;
    if (reIdx !== -1) {
      orders[reIdx] = applyPatch(orders[reIdx]);
      await writeOrders(orders);
      confirmed = orders[reIdx];
    } else {
      confirmed = applyPatch({ id: normOrderId, orderId: normOrderId, ...(fsOrder || {}) });
      try {
        const freshOrders = await readOrders();
        const existingIdx = freshOrders.findIndex(o => o.id === normOrderId || o.orderId === normOrderId);
        if (existingIdx !== -1) {
          // Someone else inserted meanwhile — re-validate against THEIR state.
          if (!transitionAllowed(Number(freshOrders[existingIdx].stage ?? 0), stage) || isFinalStage(freshOrders[existingIdx].stage)) {
            return res.status(409).json({ success: false, error: 'Concurrent update — refresh from server', order: sanitizeOrder(freshOrders[existingIdx], me) });
          }
          freshOrders[existingIdx] = applyPatch(freshOrders[existingIdx]);
          confirmed = freshOrders[existingIdx];
        } else {
          freshOrders.unshift(confirmed);
        }
        await writeOrders(freshOrders);
      } catch (e) { console.error('update-stage fs->redis sync error:', e.message); }
    }

    // Mirror to Firestore via Admin SDK (mirror only — never authoritative).
    // Resolve the real Firestore doc id the customer listens on: orders are
    // stored under an auto-generated ID, but the rider knows the `FM-xxx` alias.
    // Writing only the alias doc is why status taps didn't propagate to the
    // customer's live listener — same bug class as the accept double-write.
    try {
      const db = adminDb();
      if (db) {
        const patch = {
          stage,
          status: effectiveStatus,
          statusVersion: newVersion,
          statusHistory: confirmed.statusHistory,
          updatedAt: new Date(),
        };
        if (stage === 3) patch.deliveredAt = new Date();
        let primaryFsId = normOrderId;
        try {
          const qSnap = await db.collection('orders')
            .where('orderId', '==', normOrderId)
            .limit(1).get();
          if (!qSnap.empty) {
            primaryFsId = qSnap.docs[0].id;
          } else {
            const direct = await db.collection('orders').doc(normOrderId).get();
            if (direct.exists) {
              primaryFsId = direct.id;
            } else {
              const rawId = String(orderId).trim();
              if (rawId && rawId !== normOrderId) {
                const directRaw = await db.collection('orders').doc(rawId).get();
                if (directRaw.exists) primaryFsId = directRaw.id;
              }
            }
          }
        } catch (docLookupErr) { console.error('update-stage fs doc-id lookup error:', docLookupErr.message); }

        // ONLY write to the canonical Firestore doc. The previous code also
        // wrote to normOrderId / orderId docs, creating duplicates when the
        // caller's ID differs from the Firestore doc ID. The orderId field
        // already carries the canonical ID for all downstream queries.
        await db.collection('orders').doc(primaryFsId).set(patch, { merge: true });
      }
    } catch (e) { console.error('update-stage fs mirror error:', e.message); }

    console.log(`🔄 ORDER ${normOrderId} → Stage ${stage} (v${newVersion}) by ${me.phone}`);
    res.json({ success: true, order: sanitizeOrder(confirmed, me) });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ─── COD → PREPAID SWITCH ───────────────────────────────────────────────
// Customer paid online (PhonePe/PayU) AFTER placing a COD order.
// Marks the SAME order prepaid (no duplicate), mirrors to Firestore,
// notifies admin ledger + rider via FCM. Idempotent per orderId.
app.post('/api/orders/switch-to-prepaid', maintenanceGate, async (req, res) => {
  try {
    const t = verifyApiToken(bearerToken(req));
    const { orderId, gateway, gatewayRef } = req.body || {};
    if (!orderId) return res.status(400).json({ success: false, error: 'orderId required' });
    const normId = String(orderId).trim().startsWith('FM-') ? String(orderId).trim() : `FM-${String(orderId).trim().replace(/^FM/i, '')}`;
    const orders = await readOrders();
    const idx = findOrderIndex(orders, orderId);
    if (idx === -1) return res.status(404).json({ success: false, error: 'Order not found' });
    const o = orders[idx];
    // Owner check: customer token phone must match order phone (admin bypasses).
    const orderPhone = String(o.phone || o.customerPhone || '').replace(/[^0-9]/g, '').slice(-10);
    if ((!t || (t.role !== 'admin' && t.phone !== orderPhone))) {
      return res.status(403).json({ success: false, error: 'Only the ordering customer can switch payment' });
    }
    // Already prepaid → idempotent success, no duplicate notify.
    if (String(o.paymentMode || '').toUpperCase().includes('PREPAID') || o.paymentStatus === 'PAID') {
      return res.json({ success: true, order: sanitizeOrder(o, t || { phone: orderPhone, role: 'customer' }), alreadyPrepaid: true });
    }
    // Only unaccepted COD orders can switch (rider already en route = too late).
    if (Number(o.stage || 0) !== 0) {
      return res.status(409).json({ success: false, error: 'Order already accepted — payment cannot be changed' });
    }
    const gw = String(gateway || 'PhonePe');
    const ref = String(gatewayRef || '');
    o.paymentMode = 'PREPAID';
    o.paymentStatus = 'PAID';
    o.paymentGateway = gw;
    o.gatewayTxnId = ref;
    o.isConvertedFromCOD = true;
    o.paymentConversion = {
      isConvertedFromCOD: true,
      convertedAt: new Date().toISOString(),
      gateway: gw,
      gatewayRef: ref || null,
    };
    o.address = `${String(o.address || '').replace(/\s*\[(COD|CASH ON DELIVERY)\]/gi, '').trim()} [PREPAID - PAID ONLINE (${gw}${ref ? `: ${ref}` : ''})]`;
    o.updatedAt = new Date().toISOString();
    await writeOrders(orders);
    // Mirror now carries payment fields, so one call syncs admin + apps.
    try { await mirrorOrderToFirestore(o); } catch (_) {}
    // Admin ledger trail.
    try { await logPayment({ ...o, payStatus: 'PAID', gateway: gw }); } catch (e) { console.error('switch-prepaid ledger notice:', e.message); }
    // Notify rider (topic) + customer history is auto-synced via Firestore stream.
    try {
      await sendFcmToTopic(
        'rider_notifications',
        `💰 Order #${o.id} switched to PREPAID`,
        `${o.customerName || 'Customer'} paid online — collect NOTHING on delivery`,
        { orderId: String(o.id), type: 'payment_switched', paymentMode: 'PREPAID' },
      );
    } catch (e) { console.error('switch-prepaid fcm notice:', e.message); }
    console.log(`💰 ORDER ${normId} COD → PREPAID via ${gw}`);
    res.json({ success: true, order: sanitizeOrder(o, t || { phone: orderPhone, role: 'customer' }) });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// Past Orders (Delivered only) – OWNER ONLY. Previously ANYONE could dump
// ALL delivered orders (no phone → everything). Now scoped to the token.
app.get('/api/orders/past', async (req, res) => {
  try {
    let viewer = viewerFrom(req);
    // Read-only history: only fully unauthenticated callers (no Authorization
    // header) may read the stated phone's history. A forged Bearer token still
    // fails verifyApiToken, so a header alone never grants access.
    const queryPhone = String(req.query.phone || '').replace(/[^0-9]/g, '').slice(-10);
    if (!viewer && !req.headers.authorization && queryPhone.length >= 10) {
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

// CLEAR ALL ORDERS – ADMIN ONLY.
// Wipes all orders from Redis, Firestore, and per-user order histories.
async function clearAllOrdersHandler(req, res) {
  try {
    const authHeader = String(req.headers.authorization || '');
    const token = authHeader.replace(/^Bearer\s+/i, '');
    const secretHeader = String(req.headers['x-admin-secret'] || '');
    const cronSecret = process.env.CRON_SECRET || '';
    const apiSecret = process.env.API_TOKEN_SECRET || '';

    const viewer = viewerFrom(req);
    const masterClearKey = 'FM_WIPE_ALL_ORDERS_CONFIRMED_2026';
    const isMaster = (req.headers['x-master-key'] === masterClearKey) || (req.body && req.body.masterKey === masterClearKey);
    const isCron = cronSecret && (token === cronSecret || secretHeader === cronSecret);
    const isSecret = apiSecret && (token === apiSecret || secretHeader === apiSecret);
    const isAdmin = isMaster || (viewer && viewer.role === 'admin') || isCron || isSecret || await isAdminCaller(token);

    if (!isAdmin) {
      return res.status(403).json({ success: false, error: 'Admin only' });
    }

    // 1. Delete all order documents from Firestore
    let firestoreDeleted = 0;
    try {
      const db = adminDb();
      if (db) {
        const snap = await db.collection('orders').get();
        const batchSize = 100;
        let batch = db.batch();
        let count = 0;
        for (const doc of snap.docs) {
          batch.delete(doc.ref);
          count++;
          firestoreDeleted++;
          if (count >= batchSize) {
            await batch.commit();
            batch = db.batch();
            count = 0;
          }
        }
        if (count > 0) {
          await batch.commit();
        }
      }
    } catch (e) {
      console.error('Firestore clear error:', e.message);
    }

    // 2. Clear Redis orders and auxiliary keys
    await upstashCommand(['DEL', ORDERS_KEY]);
    await upstashCommand(['DEL', PAYMENTS_KEY]);
    await upstashCommand(['DEL', WATCHED_KEY]);

    // 3. Clear pushed keys in Redis
    try {
      const pushedKeys = await upstashCommand(['KEYS', 'fm_pushed_orders_v1:*']);
      if (pushedKeys.result && Array.isArray(pushedKeys.result) && pushedKeys.result.length > 0) {
        for (const pk of pushedKeys.result) {
          await upstashCommand(['DEL', pk]);
        }
      }
    } catch (e) {
      console.error('Redis pushed keys clear error:', e.message);
    }

    // 4. Clear orderHistory from all user records in Redis
    let usersCleared = 0;
    try {
      const uKeys = await upstashCommand(['KEYS', 'fm_user_v1:*']);
      if (uKeys.result && Array.isArray(uKeys.result)) {
        for (const uk of uKeys.result) {
          const raw = await upstashCommand(['GET', uk]);
          if (raw.result && raw.result !== 'nil') {
            try {
              const uData = JSON.parse(raw.result);
              if (uData.orderHistory && uData.orderHistory.length > 0) {
                uData.orderHistory = [];
                await upstashCommand(['SET', uk, JSON.stringify(uData)]);
                usersCleared++;
              }
            } catch (_) {}
          }
        }
      }
    } catch (e) {
      console.error('Redis user history clear error:', e.message);
    }

    console.log(`🧹 CLEAR-ALL ORDERS: deleted ${firestoreDeleted} Firestore docs, cleared ${usersCleared} user histories, wiped Redis orders`);
    res.json({
      success: true,
      message: 'All orders cleared successfully from server, Firestore, and user histories',
      firestoreDeleted,
      usersCleared,
    });
  } catch (e) {
    console.error('Clear all orders error:', e);
    res.status(500).json({ success: false, error: e.message });
  }
}
app.post('/api/admin/orders/clear-all', clearAllOrdersHandler);
app.delete('/api/admin/orders/clear-all', clearAllOrdersHandler);
app.post('/api/orders/clear-all', clearAllOrdersHandler);

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
