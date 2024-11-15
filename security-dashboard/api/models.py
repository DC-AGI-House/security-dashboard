from datetime import datetime
from pydantic import BaseModel
from typing import Optional

class SystemMetrics(BaseModel):
    cpu_percent: float
    memory_percent: float
    disk_usage: float
    network_bytes_sent: int
    network_bytes_recv: int

class BattleLog(BaseModel):
    message: str
    timestamp: datetime
    severity: str = "info"  # "info", "warning", "alert", "critical"

class SystemStatus(BaseModel):
    name: str
    status: str  # "operational", "compromised", "offline"
    load: float
    last_heartbeat: datetime
    ip_address: str