// ─────────────────────────────────────────────────────────────────────────────
// FOOD MELA — In-App Audio Calling (Agora RTC + Cloud Recording)
// Privacy: numbers stay hidden, VoIP only, channel = order_<orderId>.
// Access: only assigned customerPhone / riderId of an ACTIVE order (stage 0/1/2).
// Storage: call logs in Upstash Redis (fm_call_logs_v1). Recording files go to
// Agora Cloud Recording → AWS S3; the file URL is saved on the log.
// Mounted from server.js via registerCallRoutes(app, { readOrders }).
// ─────────────────────────────────────────────────────────────────────────────
const https = require('https');

let RtcTokenBuilder = null;
let RtcRole = null;
try {
  ({ RtcTokenBuilder, RtcRole } = require('agora-access-token'));
} catch (_) {
  console.warn('⚠️ agora-access-token not installed — /api/calls token endpoints will 501 until `npm i agora-access-token`');
}

const AGORA_APP_ID = process.env.AGORA_APP_ID || '';
const AGORA_APP_CERT = process.env.AGORA_APP_CERTIFICATE || '';
const AGORA_CUST_KEY = process.env.AGORA_CUSTOMER_KEY || '';
const AGORA_CUST_SECRET = process.env.AGORA_CUSTOMER_SECRET || '';
const S3_BUCKET = process.env.AWS_S3_BUCKET || '';
const S3_KEY = process.env.AWS_ACCESS_KEY || '';
const S3_SECRET = process.env.AWS_SECRET_KEY || '';
const S3_REGION = process.env.AWS_REGION || 'ap-south-1';

const CALL_LOGS_KEY = 'fm_call_logs_v1';
const RECORD_UID = 999999; // dedicated cloud-recording bot UID

// ─── Upstash helper (same pattern as server.js) ─────────────────────────────
const UPSTASH_URL = 'https://deciding-fish-161177.upstash.io';
const UPSTASH_TOKEN = process.env.UPSTASH_TOKEN || 'gQAAAAAAAnWZAAIgcDEwNzk0NjI3MGJiYjA0ODQ3ODE3ODk2Yjk1ODg3NGZmNA';

function upstash(cmd) {
  return new Promise((resolve, reject) => {
    const u = new URL(UPSTASH_URL);
    const body = JSON.stringify(cmd);
    const req = https.request({
      hostname: u.hostname, path: '/', method: 'POST',
      headers: { Authorization: `Bearer ${UPSTASH_TOKEN}`, 'Content-Type': 'application/json' },
    }, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => { try { resolve(JSON.parse(data)); } catch { resolve({ result: null }); } });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

async function readCallLogs() {
  try {
    const r = await upstash(['GET', CALL_LOGS_KEY]);
    if (r.result && r.result !== 'nil' && r.result !== null) return JSON.parse(r.result);
  } catch (e) { console.error('call logs read error:', e.message); }
  return [];
}

async function writeCallLogs(logs) {
  try {
    await upstash(['SET', CALL_LOGS_KEY, JSON.stringify(logs.slice(0, 500)), 'EX', '2592000']); // 30 days
  } catch (e) { console.error('call logs write error:', e.message); }
}

// ─── Agora helpers ──────────────────────────────────────────────────────────
function userIdToUid(userId) {
  const s = String(userId || '0');
  let h = 0;
  for (let i = 0; i < s.length; i++) h = ((h * 31 + s.charCodeAt(i)) >>> 0);
  return (h % 1000000) + 1; // never 0
}

function channelFor(orderId) {
  return `order_${String(orderId).replace(/[^A-Za-z0-9_-]/g, '')}`;
}

function buildToken(channel, uid) {
  const now = Math.floor(Date.now() / 1000);
  return RtcTokenBuilder.buildTokenWithUid(
    AGORA_APP_ID, AGORA_APP_CERT, channel, uid, RtcRole.PUBLISHER, now + 3600,
  );
}

function agoraRest(path, method, payload) {
  return new Promise((resolve, reject) => {
    const body = payload ? JSON.stringify(payload) : null;
    const creds = Buffer.from(`${AGORA_CUST_KEY}:${AGORA_CUST_SECRET}`).toString('base64');
    const req = https.request({
      hostname: 'api.agora.io', path, method,
      headers: { Authorization: `Basic ${creds}`, 'Content-Type': 'application/json' },
    }, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => {
        try {
          const json = JSON.parse(data || '{}');
          if (res.statusCode >= 400) reject(new Error(`Agora ${res.statusCode}: ${data}`));
          else resolve(json);
        } catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

const FIRESTORE_PROJECT = process.env.FIRESTORE_PROJECT_ID || 'food-mela-notification';

// Orders are created straight into Firestore by the apps (public read rule),
// so Redis may not have them. Fall back to the Firestore REST API (no auth
// needed — orders are publicly readable per firestore.rules).
function fetchOrderFromFirestore(orderId) {
  return new Promise((resolve) => {
    const path = `/v1/projects/${FIRESTORE_PROJECT}/databases/(default)/documents/orders/${encodeURIComponent(orderId)}`;
    const req = https.request({ hostname: 'firestore.googleapis.com', path, method: 'GET' }, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => {
        try {
          const doc = JSON.parse(data);
          const f = doc.fields || {};
          const str = (k) => (f[k] && (f[k].stringValue ?? null) !== null ? String(f[k].stringValue) : '');
          const num = (k) => (f[k] && f[k].integerValue !== undefined ? Number(f[k].integerValue) : 0);
          if (!doc.fields) return resolve(null);
          resolve({
            id: str('orderId') || orderId,
            phone: str('customerPhone'),
            acceptedBy: str('riderId') || null,
            acceptedByName: str('riderName') || null,
            stage: num('stage'),
            status: str('status'),
          });
        } catch { resolve(null); }
      });
    });
    req.on('error', () => resolve(null));
    req.setTimeout(8000, () => { req.destroy(); resolve(null); });
    req.end();
  });
}

async function findOrder(orderId, readOrders) {
  try {
    const orders = await readOrders();
    const hit = orders.find((o) => o.id === orderId);
    if (hit) return hit;
  } catch (_) {}
  return fetchOrderFromFirestore(orderId);
}

const normPhone = (p) => String(p || '').replace(/[^0-9]/g, '').slice(-10);

// Active = stage 0 (placed), 1 (accepted), 2 (out for delivery). NOT 3/-1.
function orderIsActive(order) {
  const stage = Number(order.stage ?? 0);
  return stage === 0 || stage === 1 || stage === 2;
}

// ─── Route registration ─────────────────────────────────────────────────────
function registerCallRoutes(app, { readOrders }) {
  // ── POST /api/calls/:orderId/token { userId, role? } ──
  app.post('/api/calls/:orderId/token', async (req, res) => {
    try {
      if (!RtcTokenBuilder) return res.status(501).json({ success: false, error: 'agora-access-token not installed — run npm install' });
      if (!AGORA_APP_ID || !AGORA_APP_CERT) return res.status(500).json({ success: false, error: 'AGORA_APP_ID / AGORA_APP_CERTIFICATE missing in env' });
      const { orderId } = req.params;
      const { userId, role } = req.body || {};
      if (!userId) return res.status(400).json({ success: false, error: 'userId required (customer phone or riderId)' });

      const order = await findOrder(orderId, readOrders);
      if (!order) return res.status(404).json({ success: false, error: 'Order not found' });
      if (!orderIsActive(order)) return res.status(403).json({ success: false, error: 'Order is not active — calling disabled' });

      // Membership: customer phone match OR assigned rider match
      const me = String(userId);
      const isCustomer = normPhone(me) === normPhone(order.phone) && normPhone(me).length >= 10;
      const isRider = order.acceptedBy && (me === order.acceptedBy || normPhone(me) === normPhone(order.acceptedBy));
      // Before accept (stage 0, no rider yet): only customer may fetch a token
      if (!isCustomer && !isRider) return res.status(403).json({ success: false, error: 'Not part of this order' });

      const callerRole = role || (isRider ? 'rider' : 'customer');
      const channel = channelFor(orderId);
      const uid = userIdToUid(me);
      const token = buildToken(channel, uid);
      res.json({ success: true, appId: AGORA_APP_ID, channelName: channel, token, uid, role: callerRole });
    } catch (e) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  // ── POST /api/calls/:orderId/request { callerId, callerRole?, receiverId? } ──
  app.post('/api/calls/:orderId/request', async (req, res) => {
    try {
      const { orderId } = req.params;
      const { callerId, callerRole, receiverId } = req.body || {};
      if (!callerId) return res.status(400).json({ success: false, error: 'callerId required' });
      const order = await findOrder(orderId, readOrders);
      if (!order) return res.status(404).json({ success: false, error: 'Order not found' });
      if (!orderIsActive(order)) return res.status(403).json({ success: false, error: 'Order is not active' });

      const me = String(callerId);
      const isCustomer = normPhone(me) === normPhone(order.phone) && normPhone(me).length >= 10;
      const isRider = order.acceptedBy && (me === order.acceptedBy || normPhone(me) === normPhone(order.acceptedBy));
      if (!isCustomer && !isRider) return res.status(403).json({ success: false, error: 'Not part of this order' });

      const role = callerRole || (isRider ? 'rider' : 'customer');
      const otherRole = role === 'customer' ? 'rider' : 'customer';
      const otherId = receiverId || (role === 'customer' ? (order.acceptedBy || '') : (order.phone || ''));
      if (!otherId) return res.status(409).json({ success: false, error: 'No rider assigned yet — cannot call' });

      const logs = await readCallLogs();
      const log = {
        id: `call_${Date.now()}_${Math.floor(Math.random() * 1e4)}`,
        orderId, channelName: channelFor(orderId),
        callerId: me, callerRole: role, receiverId: String(otherId), receiverRole: otherRole,
        status: 'ringing', duration: 0, recordingUrl: null,
        agoraSid: null, agoraResourceId: null,
        startedAt: null, endedAt: null, createdAt: new Date().toISOString(),
      };
      logs.unshift(log);
      await writeCallLogs(logs);
      console.log(`📞 CALL ${log.id} ringing — order ${orderId} (${role})`);
      res.status(201).json({ success: true, callId: log.id, channelName: log.channelName, log });
    } catch (e) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  // ── POST /api/calls/:orderId/record/start { callId } ──
  app.post('/api/calls/:orderId/record/start', async (req, res) => {
    try {
      const { callId } = req.body || {};
      if (!AGORA_CUST_KEY || !AGORA_CUST_SECRET) return res.status(500).json({ success: false, error: 'AGORA_CUSTOMER_KEY/SECRET missing' });
      if (!S3_BUCKET) return res.status(500).json({ success: false, error: 'AWS_S3_BUCKET missing — recording disabled' });
      const logs = await readCallLogs();
      const log = logs.find((l) => l.id === callId);
      if (!log) return res.status(404).json({ success: false, error: 'Call not found' });

      const channel = log.channelName;
      const recToken = RtcTokenBuilder
        ? RtcTokenBuilder.buildTokenWithUid(AGORA_APP_ID, AGORA_APP_CERT, channel, RECORD_UID, RtcRole.SUBSCRIBER, Math.floor(Date.now() / 1000) + 3600)
        : '';
      const acq = await agoraRest(`/v1/apps/${AGORA_APP_ID}/cloud_recording/acquire`, 'POST',
        { cname: channel, uid: String(RECORD_UID), clientRequest: {} });
      const start = await agoraRest(
        `/v1/apps/${AGORA_APP_ID}/cloud_recording/resourceid/${acq.resourceId}/mode/mix/start`, 'POST', {
          cname: channel, uid: String(RECORD_UID),
          clientRequest: {
            token: recToken,
            recordingFileConfig: { avFileType: ['mp3'] },
            storageConfig: {
              vendor: 1, region: 14, bucket: S3_BUCKET,
              accessKey: S3_KEY, secretKey: S3_SECRET,
              fileNamePrefix: ['calls', channel.replace(/^order_/, '')],
            },
          },
        });
      log.agoraResourceId = acq.resourceId;
      log.agoraSid = start.sid;
      log.status = 'accepted';
      log.startedAt = new Date().toISOString();
      await writeCallLogs(logs);
      res.json({ success: true, resourceId: acq.resourceId, sid: start.sid });
    } catch (e) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  // ── POST /api/calls/:orderId/record/stop { callId, duration? } ──
  app.post('/api/calls/:orderId/record/stop', async (req, res) => {
    try {
      const { callId, duration = 0 } = req.body || {};
      const logs = await readCallLogs();
      const log = logs.find((l) => l.id === callId);
      if (!log) return res.status(404).json({ success: false, error: 'Call not found' });

      if (log.agoraResourceId && log.agoraSid && AGORA_CUST_KEY) {
        try {
          const out = await agoraRest(
            `/v1/apps/${AGORA_APP_ID}/cloud_recording/resourceid/${log.agoraResourceId}/sid/${log.agoraSid}/mode/mix/stop`,
            'POST', { cname: log.channelName, uid: String(RECORD_UID), clientRequest: {} });
          const file = out?.serverResponse?.fileList?.[0];
          const name = typeof file === 'string' ? file : file?.fileName;
          if (name) log.recordingUrl = `https://${S3_BUCKET}.s3.${S3_REGION}.amazonaws.com/${name}`;
        } catch (e) { console.error('recording stop notice:', e.message); }
      }
      log.status = 'ended';
      log.duration = Number(duration) || 0;
      log.endedAt = new Date().toISOString();
      await writeCallLogs(logs);
      res.json({ success: true, log });
    } catch (e) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  // ── POST /api/calls/:orderId/status { callId, status, duration? } (reject/miss/cancel) ──
  app.post('/api/calls/:orderId/status', async (req, res) => {
    try {
      const { callId, status, duration = 0 } = req.body || {};
      if (!['rejected', 'missed', 'ended', 'failed'].includes(status)) {
        return res.status(400).json({ success: false, error: 'bad status' });
      }
      const logs = await readCallLogs();
      const log = logs.find((l) => l.id === callId);
      if (!log) return res.status(404).json({ success: false, error: 'Call not found' });
      log.status = status;
      if (duration) log.duration = Number(duration);
      log.endedAt = new Date().toISOString();
      await writeCallLogs(logs);
      res.json({ success: true, log });
    } catch (e) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  // ── Agora recording webhook (backup URL saver) ──
  app.post('/api/calls/recording/webhook', async (req, res) => {
    try {
      const { sid, fileList } = req.body || {};
      if (sid && Array.isArray(fileList) && fileList.length) {
        const f = fileList[0];
        const name = typeof f === 'string' ? f : f.fileName;
        if (name && S3_BUCKET) {
          const logs = await readCallLogs();
          const log = logs.find((l) => l.agoraSid === sid);
          if (log) {
            log.recordingUrl = `https://${S3_BUCKET}.s3.${S3_REGION}.amazonaws.com/${name}`;
            await writeCallLogs(logs);
          }
        }
      }
      res.json({ success: true });
    } catch (e) {
      res.status(500).json({ success: false, error: e.message });
    }
  });

  // ── ✨ GET /api/admin/orders/:orderId/call-logs ──
  app.get('/api/admin/orders/:orderId/call-logs', async (req, res) => {
    try {
      const logs = await readCallLogs();
      const list = logs.filter((l) => l.orderId === req.params.orderId);
      res.json({ success: true, orderId: req.params.orderId, count: list.length, logs: list });
    } catch (e) {
      res.status(500).json({ success: false, error: e.message });
    }
  });
}

module.exports = { registerCallRoutes, channelFor, userIdToUid };
