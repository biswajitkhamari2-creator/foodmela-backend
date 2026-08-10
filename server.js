const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST', 'DELETE'] }
});

// ─── IN-MEMORY DATABASE ──────────────────────────────────────────────────────
// In production, replace these with a real DB like MongoDB/PostgreSQL
let liveOrders = [];

// User accounts: { phone -> { name, email, addresses: [], orderHistory: [] } }
const users = {};

function getOrCreateUser(phone) {
  if (!users[phone]) {
    users[phone] = {
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
    console.log(`👤 New user registered: ${phone}`);
  }
  return users[phone];
}

// ─── HEALTH CHECK ────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({
    status: 'ONLINE 🚀',
    service: 'FOOD MELA Real-Time Cloud API',
    totalLiveOrders: liveOrders.length,
    totalUsers: Object.keys(users).length,
    timestamp: new Date().toISOString()
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// USER PROFILE ENDPOINTS
// ═══════════════════════════════════════════════════════════════════════════════

// GET user profile by phone
app.get('/api/user/:phone', (req, res) => {
  const { phone } = req.params;
  const user = getOrCreateUser(phone);
  res.json({ success: true, user });
});

// UPDATE user profile (name, email)
app.post('/api/user/:phone/profile', (req, res) => {
  const { phone } = req.params;
  const { name, email } = req.body;
  const user = getOrCreateUser(phone);
  if (name) user.name = name;
  if (email) user.email = email;
  console.log(`✏️ Profile updated for: ${phone}`);
  res.json({ success: true, user });
});

// ═══════════════════════════════════════════════════════════════════════════════
// ADDRESS ENDPOINTS
// ═══════════════════════════════════════════════════════════════════════════════

// GET all saved addresses for user
app.get('/api/user/:phone/addresses', (req, res) => {
  const { phone } = req.params;
  const user = getOrCreateUser(phone);
  res.json({ success: true, addresses: user.addresses });
});

// ADD new address
app.post('/api/user/:phone/addresses', (req, res) => {
  const { phone } = req.params;
  const { title, address } = req.body;
  if (!title || !address) {
    return res.status(400).json({ success: false, error: 'title and address required' });
  }
  const user = getOrCreateUser(phone);
  // Remove duplicate title
  user.addresses = user.addresses.filter(a => a.title !== title);
  user.addresses.push({ title, address });
  console.log(`📍 Address saved for ${phone}: ${title}`);
  res.json({ success: true, addresses: user.addresses });
});

// DELETE address by title
app.delete('/api/user/:phone/addresses/:title', (req, res) => {
  const { phone, title } = req.params;
  const user = getOrCreateUser(phone);
  user.addresses = user.addresses.filter(a => a.title !== decodeURIComponent(title));
  res.json({ success: true, addresses: user.addresses });
});

// ═══════════════════════════════════════════════════════════════════════════════
// ORDER ENDPOINTS
// ═══════════════════════════════════════════════════════════════════════════════

// GET live orders (for Driver App polling)
app.get('/api/orders/live', (req, res) => {
  res.json({ success: true, orders: liveOrders });
});

// GET order history for user
app.get('/api/user/:phone/orders', (req, res) => {
  const { phone } = req.params;
  const user = getOrCreateUser(phone);
  res.json({ success: true, orders: user.orderHistory });
});

// Place New Order
app.post('/api/orders/create', (req, res) => {
  const { customerName, phone, address, items, totalAmount } = req.body;
  const orderId = req.body.id || `FM-${Math.floor(1000 + Math.random() * 9000)}`;

  const newOrder = {
    id: orderId,
    customerName: customerName || 'Customer',
    phone: phone || 'unknown',
    address: address || 'Bhubaneswar',
    items: items || 'Food items',
    total: `₹${Math.floor(totalAmount || 0)}`,
    amountValue: totalAmount || 0,
    status: 'Order Placed & Waiting for Delivery Boy 📝🍳',
    stage: 0,
    timestamp: new Date().toISOString()
  };

  liveOrders.unshift(newOrder);

  // Save to user order history
  if (phone && phone !== 'unknown') {
    const user = getOrCreateUser(phone);
    user.orderHistory.unshift(newOrder);
    // Keep last 50 orders
    if (user.orderHistory.length > 50) user.orderHistory = user.orderHistory.slice(0, 50);
  }

  // Keep max 100 live orders
  if (liveOrders.length > 100) liveOrders = liveOrders.slice(0, 100);

  // Broadcast to all connected Socket.IO Drivers instantly (< 50ms)
  io.emit('new_order_incoming', newOrder);
  console.log(`🔔 NEW ORDER BROADCASTED TO DRIVERS: ${orderId}`);

  res.status(201).json({ success: true, order: newOrder });
});

// Cancel Order
app.post('/api/orders/cancel', (req, res) => {
  const { orderId } = req.body;
  const targetId = orderId || (liveOrders.length > 0 ? liveOrders[0].id : null);
  if (!targetId) return res.status(400).json({ success: false, error: 'orderId required' });

  let cancelledOrder = null;
  for (let order of liveOrders) {
    if (order.id === targetId) {
      order.stage = -1;
      order.status = 'CANCELLED BY CUSTOMER 🚨';
      cancelledOrder = order;
      break;
    }
  }

  if (!cancelledOrder) {
    cancelledOrder = { id: targetId, status: 'CANCELLED BY CUSTOMER 🚨', stage: -1 };
  }

  io.emit('order_cancelled', cancelledOrder);
  console.log(`🚨 ORDER CANCELLED & BROADCASTED: ${targetId}`);
  res.json({ success: true, cancelledOrder });
});

// Update Order Stage
app.post('/api/orders/update-stage', (req, res) => {
  const { orderId, newStage } = req.body;
  let updatedOrder = null;
  for (let order of liveOrders) {
    if (order.id === orderId) {
      order.stage = newStage;
      if (newStage === 1) order.status = 'Preparing in Kitchen 🍳';
      else if (newStage === 2) order.status = 'On the Way (Out for Delivery) 🛵';
      else if (newStage === 3) order.status = 'Delivered 🏁';
      updatedOrder = order;
      break;
    }
  }
  io.emit('order_stage_updated', { orderId, newStage, updatedOrder });
  res.json({ success: true, order: updatedOrder });
});

// ─── SOCKET.IO ───────────────────────────────────────────────────────────────
io.on('connection', (socket) => {
  console.log(`📱 Client Connected: ${socket.id}`);
  socket.emit('live_orders_snapshot', liveOrders);
  socket.on('disconnect', () => {
    console.log(`📱 Client Disconnected: ${socket.id}`);
  });
});

// ─── START ───────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`=================================================`);
  console.log(`🚀 FOOD MELA Real-Time Cloud Backend API Active!`);
  console.log(`📍 http://localhost:${PORT}`);
  console.log(`=================================================`);
});
