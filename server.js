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
let liveOrders = [];      // pending/active orders visible to ALL drivers
let completedOrders = []; // accepted/delivered orders (assigned to specific driver)

// User accounts: phone -> { name, email, addresses, orderHistory }
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
    console.log(`👤 New user: ${phone}`);
  }
  return users[phone];
}

// ─── HEALTH CHECK ────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({
    status: 'ONLINE 🚀',
    service: 'FOOD MELA Real-Time Cloud API v2.0',
    liveOrders: liveOrders.length,
    completedOrders: completedOrders.length,
    totalUsers: Object.keys(users).length,
    timestamp: new Date().toISOString()
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// USER PROFILE ENDPOINTS
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/user/:phone', (req, res) => {
  const user = getOrCreateUser(req.params.phone);
  res.json({ success: true, user });
});

app.post('/api/user/:phone/profile', (req, res) => {
  const user = getOrCreateUser(req.params.phone);
  if (req.body.name) user.name = req.body.name;
  if (req.body.email) user.email = req.body.email;
  res.json({ success: true, user });
});

// ═══════════════════════════════════════════════════════════════════════════════
// ADDRESS ENDPOINTS
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/user/:phone/addresses', (req, res) => {
  const user = getOrCreateUser(req.params.phone);
  res.json({ success: true, addresses: user.addresses });
});

app.post('/api/user/:phone/addresses', (req, res) => {
  const { title, address } = req.body;
  if (!title || !address) return res.status(400).json({ success: false, error: 'title and address required' });
  const user = getOrCreateUser(req.params.phone);
  user.addresses = user.addresses.filter(a => a.title !== title);
  user.addresses.push({ title, address });
  console.log(`📍 Address saved for ${req.params.phone}: ${title}`);
  res.json({ success: true, addresses: user.addresses });
});

app.delete('/api/user/:phone/addresses/:title', (req, res) => {
  const user = getOrCreateUser(req.params.phone);
  user.addresses = user.addresses.filter(a => a.title !== decodeURIComponent(req.params.title));
  res.json({ success: true, addresses: user.addresses });
});

// ═══════════════════════════════════════════════════════════════════════════════
// ORDER ENDPOINTS
// ═══════════════════════════════════════════════════════════════════════════════

// GET live (unaccepted) orders — for ALL driver apps polling
app.get('/api/orders/live', (req, res) => {
  // Only return stage 0 (waiting) and stage -1 (cancelled) orders
  const pending = liveOrders.filter(o => o.stage === 0 || o.stage === -1);
  res.json({ success: true, orders: pending });
});

// GET completed orders (accepted+delivered) — for driver history
app.get('/api/orders/completed', (req, res) => {
  const { driverId } = req.query;
  const orders = driverId
    ? completedOrders.filter(o => o.acceptedBy === driverId)
    : completedOrders;
  res.json({ success: true, orders });
});

// GET order history for a customer phone
app.get('/api/user/:phone/orders', (req, res) => {
  const user = getOrCreateUser(req.params.phone);
  res.json({ success: true, orders: user.orderHistory });
});

// Place New Order — broadcast to ALL connected drivers
app.post('/api/orders/create', (req, res) => {
  const { customerName, phone, address, items, totalAmount } = req.body;
  const orderId = req.body.id || `FM-${Math.floor(1000 + Math.random() * 9000)}`;

  // Check duplicate
  if (liveOrders.find(o => o.id === orderId)) {
    return res.status(200).json({ success: true, order: liveOrders.find(o => o.id === orderId), duplicate: true });
  }

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
    acceptedBy: null,
    timestamp: new Date().toISOString()
  };

  liveOrders.unshift(newOrder);

  // Save to customer order history
  if (phone && phone !== 'unknown') {
    const user = getOrCreateUser(phone);
    user.orderHistory.unshift({ ...newOrder, orderStatus: 'placed' });
    if (user.orderHistory.length > 50) user.orderHistory = user.orderHistory.slice(0, 50);
  }

  if (liveOrders.length > 200) liveOrders = liveOrders.slice(0, 200);

  // 🔔 BROADCAST to ALL connected drivers instantly via Socket.IO
  io.emit('new_order_incoming', newOrder);
  console.log(`🔔 NEW ORDER → ALL DRIVERS: ${orderId}`);

  res.status(201).json({ success: true, order: newOrder });
});

// ✅ ACCEPT ORDER — first driver to accept wins; auto-removes from others
app.post('/api/orders/accept', (req, res) => {
  const { orderId, driverId, driverName } = req.body;
  if (!orderId) return res.status(400).json({ success: false, error: 'orderId required' });

  const orderIdx = liveOrders.findIndex(o => o.id === orderId);
  if (orderIdx === -1) {
    return res.status(409).json({ success: false, error: 'Order already accepted by another driver' });
  }

  const order = liveOrders[orderIdx];

  // Already accepted by someone else?
  if (order.acceptedBy && order.acceptedBy !== driverId) {
    return res.status(409).json({ success: false, error: `Order already accepted by ${order.acceptedBy}` });
  }

  // Mark as accepted
  order.stage = 1;
  order.status = 'Preparing in Kitchen 🍳';
  order.acceptedBy = driverId || 'driver';
  order.acceptedByName = driverName || 'Delivery Partner';
  order.acceptedAt = new Date().toISOString();

  // Move from liveOrders to completedOrders
  liveOrders.splice(orderIdx, 1);
  completedOrders.unshift(order);
  if (completedOrders.length > 500) completedOrders = completedOrders.slice(0, 500);

  // 📢 Broadcast to ALL drivers: "This order is taken — remove from your list"
  io.emit('order_accepted', { orderId, acceptedBy: order.acceptedBy, acceptedByName: order.acceptedByName });
  console.log(`✅ ORDER ${orderId} ACCEPTED by ${order.acceptedBy} → removed from all drivers`);

  res.json({ success: true, order });
});

// Cancel Order (by customer)
app.post('/api/orders/cancel', (req, res) => {
  const { orderId } = req.body;
  if (!orderId) return res.status(400).json({ success: false, error: 'orderId required' });

  let cancelledOrder = null;

  // Search in liveOrders first
  const liveIdx = liveOrders.findIndex(o => o.id === orderId);
  if (liveIdx !== -1) {
    liveOrders[liveIdx].stage = -1;
    liveOrders[liveIdx].status = 'CANCELLED BY CUSTOMER 🚨';
    cancelledOrder = liveOrders[liveIdx];
  } else {
    // Try completedOrders
    const compIdx = completedOrders.findIndex(o => o.id === orderId);
    if (compIdx !== -1) {
      completedOrders[compIdx].stage = -1;
      completedOrders[compIdx].status = 'CANCELLED BY CUSTOMER 🚨';
      cancelledOrder = completedOrders[compIdx];
    }
  }

  if (!cancelledOrder) {
    cancelledOrder = { id: orderId, status: 'CANCELLED BY CUSTOMER 🚨', stage: -1 };
  }

  // 📢 Broadcast cancellation to all drivers
  io.emit('order_cancelled', cancelledOrder);
  console.log(`🚨 ORDER ${orderId} CANCELLED → notified all drivers`);

  res.json({ success: true, cancelledOrder });
});

// Update Order Stage
app.post('/api/orders/update-stage', (req, res) => {
  const { orderId, newStage } = req.body;
  let updatedOrder = null;

  for (let order of [...liveOrders, ...completedOrders]) {
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
  console.log(`📱 Driver Connected: ${socket.id}`);
  // Send current pending orders snapshot
  const pending = liveOrders.filter(o => o.stage === 0);
  socket.emit('live_orders_snapshot', pending);

  socket.on('disconnect', () => {
    console.log(`📱 Driver Disconnected: ${socket.id}`);
  });
});

// ─── START ───────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`=================================================`);
  console.log(`🚀 FOOD MELA Real-Time Cloud Backend v2.0 Active!`);
  console.log(`📍 http://localhost:${PORT}`);
  console.log(`=================================================`);
});
