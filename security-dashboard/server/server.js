const express = require('express');
const WebSocket = require('ws');
const cors = require('cors');
const http = require('http');

// Initialize Express app
const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Store latest data
let currentMetrics = {
  cpu_percent: 0,
  memory_percent: 0,
  disk_usage: 0,
  network_bytes_sent: 0,
  network_bytes_recv: 0,
  memory_used: 0,
  memory_total: 0,
  disk_used: 0,
  disk_total: 0
};

let battleLogs = [];
let defenseActions = [];
let defenseCode = [];

// Middleware
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept'],
  credentials: true,
  maxAge: 86400 // 24 hours
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Helper function to create API response format
const createApiResponse = (content) => ({
  model: "c2-defender-v1",
  created_at: new Date().toISOString(),
  message: {
    role: "system",
    content: content
  },
  done_reason: "completed",
  done: true
});

// Broadcast helper function
const broadcastToClients = (type, data) => {
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify({ type, data }));
    }
  });
};

// REST Endpoints
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    connections: wss.clients.size,
    battle_logs: battleLogs.length,
    defense_actions: defenseActions.length,
    defense_code: defenseCode.length
  });
});

app.get('/system-metrics', (req, res) => {
  res.json(createApiResponse({
    ...currentMetrics,
    code: defenseCode
  }));
});

app.get('/battle-logs', (req, res) => {
  res.json(createApiResponse(battleLogs));
});

app.get('/defense-code', (req, res) => {
  res.json(createApiResponse(defenseCode));
});

// New endpoint to get defense actions
app.get('/defense-actions', (req, res) => {
  // Optional query parameters for filtering
  const { limit, status, timeframe } = req.query;
  let filteredActions = [...defenseActions];

  // Apply filters if provided
  if (status) {
    filteredActions = filteredActions.filter(action => action.status === status);
  }

  if (timeframe) {
    const timeframeMs = parseInt(timeframe) * 60 * 1000; // Convert minutes to milliseconds
    const cutoffTime = Date.now() - timeframeMs;
    filteredActions = filteredActions.filter(action => 
      new Date(action.timestamp).getTime() > cutoffTime
    );
  }

  // Apply limit if provided
  if (limit) {
    filteredActions = filteredActions.slice(-parseInt(limit));
  }

  res.json(createApiResponse({
    total: defenseActions.length,
    filtered: filteredActions.length,
    actions: filteredActions
  }));
});

app.post('/battle-logs', (req, res) => {
  const newLog = {
    id: Date.now().toString(),
    timestamp: new Date().toISOString(),
    ...req.body
  };
  
  battleLogs.push(newLog);
  
  if (battleLogs.length > 100) {
    battleLogs = battleLogs.slice(-100);
  }
  
  broadcastToClients('battle_logs', battleLogs);
  res.json(createApiResponse({ status: 'success' }));
});

app.post('/defense-action', (req, res) => {
  const code = req.body.code || req.body;  // Accept either {code: string} or direct string
  
  const newAction = {
    id: Date.now().toString(),
    timestamp: new Date().toISOString(),
    status: 'active',
    code: typeof code === 'string' ? code : String(code)
  };
  
  if (newAction.code) {
    defenseCode.unshift(newAction.code);
    defenseActions.push(newAction);
    
    if (defenseCode.length > 100) {
      defenseCode = defenseCode.slice(0, 100);
    }
    if (defenseActions.length > 100) {
      defenseActions = defenseActions.slice(-100);
    }
    
    broadcastToClients('defense_update', newAction);
  }
  
  res.json(createApiResponse({
    status: 'success',
    action: newAction
  }));
});

// WebSocket connection handling
wss.on('connection', (ws) => {
  console.log('Client connected');
  
  const initialData = createApiResponse({
    type: 'initial_data',
    data: {
      metrics: currentMetrics,
      logs: battleLogs,
      defenseActions: defenseActions,
      code: defenseCode
    }
  });
  ws.send(JSON.stringify(initialData));

  ws.on('close', () => {
    console.log('Client disconnected');
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json(createApiResponse({
    error: 'Internal server error',
    message: err.message
  }));
});

// Start server
const PORT = process.env.PORT || 8000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`WebSocket server available at ws://localhost:${PORT}`);
  console.log(`HTTP server available at http://localhost:${PORT}`);
});