// ─────────────────────────────────────────────────────────────────────────────
// FOOD MELA BACKEND  –  Express + Upstash Redis (persistent, serverless-safe)
// All user and order states are stored persistently in Upstash Redis.
// Fully backward compatible with all original Customer & Driver App endpoints.
// ─────────────────────────────────────────────────────────────────────────────
const express = require('express');
const cors    = require('cors');
const https   = require('https');

const app = express();
app.use(cors());
app.use(express.json());

// ─── UPSTASH REDIS CONFIG ─────────────────────────────────────────────────────
const UPSTASH_URL   = 'https://deciding-fish-161177.upstash.io';
const UPSTASH_TOKEN = 'gQAAAAAAAnWZAAIgcDEwNzk0NjI3MGJiYjA0ODQ3ODE3ODk2Yjk1ODg3NGZmNA';

const ORDERS_KEY    = 'fm_orders_v1';

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

// ═══════════════════════════════════════════════════════════════════════════════
// USER PROFILE ENDPOINTS
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/user/:phone', async (req, res) => {
  const user = await readUser(req.params.phone);
  res.json({ success: true, user });
});

app.post('/api/user/:phone/profile', async (req, res) => {
  const phone = req.params.phone;
  const user = await readUser(phone);
  if (req.body.name) user.name = req.body.name;
  if (req.body.email) user.email = req.body.email;
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

app.post('/api/auth/phone-email/verify', async (req, res) => {
  try {
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
    res.json({ success: true, phone, jwt: data.ph_email_jwt || null });
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

app.get('/api/user/:phone/addresses', async (req, res) => {
  const user = await readUser(req.params.phone);
  res.json({ success: true, addresses: user.addresses });
});

app.post('/api/user/:phone/addresses', async (req, res) => {
  const { title, address } = req.body;
  if (!title || !address) return res.status(400).json({ success: false, error: 'title and address required' });
  const phone = req.params.phone;
  const user = await readUser(phone);
  user.addresses = user.addresses.filter(a => a.title !== title);
  user.addresses.push({ title, address });
  await writeUser(phone, user);
  console.log(`📍 Address saved for ${phone}: ${title}`);
  res.json({ success: true, addresses: user.addresses });
});

app.delete('/api/user/:phone/addresses/:title', async (req, res) => {
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

// GET live (unaccepted) orders – for ALL driver apps polling
app.get('/api/orders/live', async (req, res) => {
  try {
    const orders = await readOrders();
    const live = orders.filter(o => o.stage === 0 || o.stage === -1);
    res.json({ success: true, orders: live });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// GET completed orders (accepted+delivered) – for driver history
app.get('/api/orders/completed', async (req, res) => {
  try {
    const { driverId } = req.query;
    const orders = await readOrders();
    const completed = orders.filter(o =>
      o.stage >= 1 &&
      (!driverId || o.acceptedBy === driverId)
    );
    res.json({ success: true, orders: completed });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// GET order history for a customer phone
app.get('/api/user/:phone/orders', async (req, res) => {
  try {
    const user = await readUser(req.params.phone);
    res.json({ success: true, orders: user.orderHistory || [] });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// GET single order status for customer live tracking
app.get('/api/orders/status/:orderId', async (req, res) => {
  try {
    const orders = await readOrders();
    const order  = orders.find(o => o.id === req.params.orderId);
    if (!order) return res.status(404).json({ success: false, error: 'Order not found' });
    res.json({ success: true, order });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// Place New Order – Supports BOTH `/api/orders/place` and `/api/orders/create`
const placeOrderHandler = async (req, res) => {
  try {
    const { customerName, phone, address, items, totalAmount } = req.body;
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
    res.status(201).json({ success: true, order: newOrder });
  } catch (e) {
    console.error('Place order error:', e);
    res.status(500).json({ success: false, error: e.message });
  }
};

app.post('/api/orders/place', placeOrderHandler);
app.post('/api/orders/create', placeOrderHandler);

// ✅ ACCEPT ORDER – first driver to accept wins; enforces blocking/approval
app.post('/api/orders/accept', async (req, res) => {
  try {
    const { orderId, driverId, driverName } = req.body;
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

// Cancel Order (by customer)
app.post('/api/orders/cancel', async (req, res) => {
  try {
    const { orderId } = req.body;
    if (!orderId) return res.status(400).json({ success: false, error: 'orderId required' });

    const orders = await readOrders();
    const idx    = orders.findIndex(o => o.id === orderId);

    let cancelledOrder;
    if (idx !== -1) {
      orders[idx] = {
        ...orders[idx],
        stage:       -1,
        status:      'CANCELLED BY CUSTOMER 🚨',
        cancelledAt: new Date().toISOString(),
        updatedAt:   new Date().toISOString(),
      };
      cancelledOrder = orders[idx];
    } else {
      cancelledOrder = {
        id: orderId, stage: -1,
        status: 'CANCELLED BY CUSTOMER 🚨',
        cancelledAt: new Date().toISOString(),
        updatedAt:   new Date().toISOString(),
      };
      orders.unshift(cancelledOrder);
    }

    await writeOrders(orders);
    console.log(`🚨 ORDER ${orderId} CANCELLED`);
    res.json({ success: true, cancelledOrder });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// Update Order Stage
app.post('/api/orders/update-stage', async (req, res) => {
  try {
    const { orderId, newStage } = req.body;
    if (!orderId || newStage === undefined) {
      return res.status(400).json({ success: false, error: 'orderId and newStage required' });
    }

    const orders = await readOrders();
    const idx    = orders.findIndex(o => o.id === orderId);
    if (idx === -1) return res.status(404).json({ success: false, error: 'Order not found' });

    const statusMap = {
      1: 'Preparing in Kitchen 🍳',
      2: 'On the Way (Out for Delivery) 🛵',
      3: 'Delivered 🏁',
    };

    orders[idx] = {
      ...orders[idx],
      stage:     newStage,
      status:    statusMap[newStage] || 'In Progress',
      updatedAt: new Date().toISOString(),
    };

    await writeOrders(orders);
    console.log(`🔄 ORDER ${orderId} → Stage ${newStage}`);
    res.json({ success: true, order: orders[idx] });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// Past Orders (Delivered only)
app.get('/api/orders/past', async (req, res) => {
  try {
    const { phone, customerName } = req.query;
    const orders = await readOrders();
    const past = orders.filter(o =>
      o.stage === 3 &&
      (
        (phone        && o.phone        === phone) ||
        (customerName && o.customerName === customerName) ||
        (!phone && !customerName)
      )
    );
    res.json({ success: true, orders: past });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// CLEAR OLD ORDERS
app.delete('/api/orders/clear-delivered', async (req, res) => {
  try {
    const orders = await readOrders();
    const kept = orders.filter(o => o.stage < 3);
    await writeOrders(kept);
    res.json({ success: true, removed: orders.length - kept.length });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ─── START SERVER ─────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Food Mela Backend running on port ${PORT}`));

module.exports = app;
