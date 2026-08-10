const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  }
});

// In-Memory Live Orders DB
let liveOrders = [];

// REST API Endpoints
app.get('/', (req, res) => {
  res.json({
    status: 'ONLINE 🚀',
    service: 'FOOD MELA Real-Time Cloud API',
    totalLiveOrders: liveOrders.length,
    timestamp: new Date().toISOString()
  });
});

app.get('/api/orders/live', (req, res) => {
  res.json({ success: true, orders: liveOrders });
});

// Place New Order
app.post('/api/orders/create', (req, res) => {
  const { customerName, address, items, totalAmount } = req.body;
  const orderId = `FM-${Math.floor(1000 + Math.random() * 9000)}`;

  const newOrder = {
    id: orderId,
    customerName: customerName || 'Amit Kumar',
    address: address || 'Saheed Nagar, Janpath Road, Bhubaneswar',
    items: items || '1x Chicken Biryani, 1kg Fresh Tomato',
    total: `₹${totalAmount || 490}`,
    amountValue: totalAmount || 490,
    status: 'Order Placed & Waiting for Delivery Boy 📝🍳',
    stage: 0,
    timestamp: new Date().toISOString()
  };

  liveOrders.unshift(newOrder);

  // Broadcast to all connected Socket.IO Drivers instantly (< 50ms)
  io.emit('new_order_incoming', newOrder);
  console.log(`🔔 NEW ORDER PLACED & BROADCASTED TO DRIVERS: ${orderId}`);

  res.status(201).json({ success: true, order: newOrder });
});

// Cancel Order
app.post('/api/orders/cancel', (req, res) => {
  const { orderId } = req.body;
  const targetId = orderId || (liveOrders.length > 0 ? liveOrders[0].id : 'FM-9934');

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
    cancelledOrder = {
      id: targetId,
      customerName: 'Amit Kumar',
      address: 'Saheed Nagar',
      items: '1x Chicken Biryani',
      total: '₹490',
      status: 'CANCELLED BY CUSTOMER 🚨',
      stage: -1
    };
  }

  // Broadcast Cancellation to all connected Socket.IO Drivers instantly (< 50ms)
  io.emit('order_cancelled', cancelledOrder);
  console.log(`🚨 ORDER CANCELLED & BROADCASTED TO DRIVERS: ${targetId}`);

  res.json({ success: true, cancelledOrder });
});

// Update Order Stage (Driver Accept / Preparation / Delivery)
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

// Socket.IO Real-Time Gateway Connection
io.on('connection', (socket) => {
  console.log(`📱 Client Connected to Real-Time Bridge: ${socket.id}`);
  socket.emit('live_orders_snapshot', liveOrders);

  socket.on('disconnect', () => {
    console.log(`📱 Client Disconnected: ${socket.id}`);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`=================================================`);
  console.log(`🚀 FOOD MELA Real-Time Cloud Backend API Active!`);
  console.log(`📍 Listening on: http://localhost:${PORT}`);
  console.log(`=================================================`);
});
