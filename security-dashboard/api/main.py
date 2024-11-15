from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
from typing import List, Dict
import psutil
import asyncio
import uuid
from collections import deque
from pydantic import BaseModel

app = FastAPI(title="Cyber Command API")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Your Next.js frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Data Models
class BattleLog(BaseModel):
    message: str
    timestamp: str
    severity: str

class DefenseAction(BaseModel):
    id: str
    timestamp: str
    type: str
    code: str
    status: str
    description: str

# Global Storage
active_connections: List[WebSocket] = []
battle_logs = deque(maxlen=100)
defense_actions: List[Dict] = []

# Utility Functions
def get_network_speed():
    """Get current network counters"""
    net = psutil.net_io_counters()
    return {
        "bytes_sent": net.bytes_sent,
        "bytes_recv": net.bytes_recv
    }

async def broadcast_to_clients(message_type: str, data: dict):
    """Broadcast updates to all connected clients"""
    for connection in active_connections:
        try:
            await connection.send_json({
                "type": message_type,
                "data": data
            })
        except:
            pass

# API Routes
@app.get("/")
async def root():
    return {
        "message": "Cyber Command API is running",
        "version": "1.0.0",
        "status": "operational"
    }

@app.get("/system-metrics")
async def get_metrics():
    """Get current system metrics"""
    network = get_network_speed()
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    return {
        "cpu_percent": psutil.cpu_percent(),
        "memory_percent": memory.percent,
        "memory_used": memory.used,
        "memory_total": memory.total,
        "disk_usage": disk.percent,
        "disk_used": disk.used,
        "disk_total": disk.total,
        "network_bytes_sent": network["bytes_sent"],
        "network_bytes_recv": network["bytes_recv"],
        "timestamp": datetime.now().isoformat()
    }

@app.post("/api/battle-log")
async def add_battle_log(log: BattleLog):
    """Add a new battle log entry"""
    log_entry = {
        "message": log.message,
        "timestamp": log.timestamp,
        "severity": log.severity
    }
    battle_logs.append(log_entry)
    
    await broadcast_to_clients("battle_logs", list(battle_logs))
    return {"status": "success"}

@app.post("/api/defense-action")
async def add_defense_action(action: DefenseAction):
    """Add a new defense action"""
    action_entry = {
        "id": action.id or str(uuid.uuid4()),
        "timestamp": action.timestamp,
        "type": action.type,
        "code": action.code,
        "status": action.status,
        "description": action.description
    }
    defense_actions.append(action_entry)
    
    await broadcast_to_clients("defense_actions", defense_actions)
    return {"status": "success"}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    
    try:
        while True:
            # Send system metrics
            metrics = await get_metrics()
            await websocket.send_json({
                "type": "system_metrics",
                "data": metrics
            })
            
            # Send battle logs
            await websocket.send_json({
                "type": "battle_logs",
                "data": list(battle_logs)
            })
            
            # Send defense actions
            await websocket.send_json({
                "type": "defense_actions",
                "data": defense_actions
            })
            
            await asyncio.sleep(1)
            
    except Exception as e:
        print(f"WebSocket error: {e}")
    finally:
        active_connections.remove(websocket)

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "connections": len(active_connections),
        "battle_logs": len(battle_logs),
        "defense_actions": len(defense_actions)
    }

# Dummy Data
DUMMY_DEFENSE_ACTIONS = [
    {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now().isoformat(),
        "type": "firewall",
        "status": "active",
        "description": "Updating firewall rules to block suspicious IP range",
        "code": """iptables -A INPUT -s 192.168.1.0/24 -j DROP
iptables -A OUTPUT -d 192.168.1.0/24 -j DROP
systemctl restart firewalld"""
    },
    {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now().isoformat(),
        "type": "ids",
        "status": "completed",
        "description": "Updated Snort rules for SQL injection detection",
        "code": """alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
  msg:"SQL Injection Attempt";
  flow:to_server,established;
  content:"UNION SELECT"; nocase;
  sid:1000001; rev:1;
)"""
    },
    {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now().isoformat(),
        "type": "authentication",
        "status": "pending",
        "description": "Implementing additional 2FA checks",
        "code": """from django.contrib.auth.decorators import user_passes_test
def require_2fa(view_func):
    def check_2fa(user):
        return user.is_authenticated and user.has_2fa_enabled
    decorated_view = user_passes_test(check_2fa)(view_func)
    return decorated_view"""
    }
]

DUMMY_BATTLE_LOGS = [
    {"message": "System startup initiated", "severity": "info"},
    {"message": "Firewall rules updated", "severity": "info"},
    {"message": "Suspicious login attempt blocked", "severity": "warning"},
    {"message": "Port scan detected", "severity": "alert"},
    {"message": "Multiple failed login attempts", "severity": "warning"},
    {"message": "System update completed", "severity": "info"},
    {"message": "Network anomaly detected", "severity": "alert"},
    {"message": "Backup process completed", "severity": "info"},
    {"message": "Potential data breach attempt", "severity": "critical"},
    {"message": "IDS signature updated", "severity": "info"}
]

@app.on_event("startup")
async def add_dummy_data():
    """Initialize with dummy data if none exists"""
    if len(battle_logs) == 0:
        for log in DUMMY_BATTLE_LOGS:
            battle_logs.append({
                **log,
                "timestamp": datetime.now().isoformat()
            })
    
    if len(defense_actions) == 0:
        defense_actions.extend(DUMMY_DEFENSE_ACTIONS)


@app.websocket("/ws/defense")
async def defense_websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    
    # Sample defense templates
    defense_templates = [
        {
            "description": "Generating firewall rules for detected threat",
            "code": """iptables -A INPUT -s {ip} -j DROP
iptables -A OUTPUT -d malicious-domain.com -j DROP
systemctl restart firewalld""",
        },
        {
            "description": "Implementing rate limiting for suspicious activity",
            "code": """limit_req_zone $binary_remote_addr zone=mylimit:10m rate=10r/s;
limit_req zone=mylimit burst=20 nodelay;
deny all;""",
        },
        {
            "description": "Deploying additional authentication checks",
            "code": """@require_authentication
def secure_endpoint():
    if not verify_2fa(current_user):
        raise SecurityException("2FA Required")
    if is_suspicious_ip(request.remote_addr):
        raise SecurityException("IP Blocked")
    return proceed()""",
        }
    ]
    
    try:
        while True:
            # Generate random defense action
            template = random.choice(defense_templates)
            action = {
                "id": str(random.randint(1000, 9999)),
                "timestamp": datetime.now().isoformat(),
                "description": template["description"],
                "code": template["code"].format(
                    ip=f"{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
                ),
                "status": "active"
            }
            
            # Send defense update
            await websocket.send_json({
                "type": "defense_update",
                "action": action
            })
            
            # Wait before sending next update
            await asyncio.sleep(random.randint(8, 15))
    except Exception as e:
        print(f"Defense WebSocket error: {e}")