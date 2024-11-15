import psutil
from datetime import datetime
from .models import SystemMetrics, SystemStatus

def get_system_metrics() -> SystemMetrics:
    """Get current system metrics using psutil"""
    cpu = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory().percent
    disk = psutil.disk_usage('/').percent
    network = psutil.net_io_counters()
    
    return SystemMetrics(
        cpu_percent=cpu,
        memory_percent=memory,
        disk_usage=disk,
        network_bytes_sent=network.bytes_sent,
        network_bytes_recv=network.bytes_recv
    )

def get_system_status() -> SystemStatus:
    """Get overall system status"""
    try:
        # Get the first available network interface's IP
        ip = [i for i in psutil.net_if_addrs().values()][0][0].address
    except:
        ip = "127.0.0.1"
        
    return SystemStatus(
        name="MainSystem",
        status="operational",
        load=psutil.getloadavg()[0],
        last_heartbeat=datetime.now(),
        ip_address=ip
    )

def format_bytes(bytes: int) -> str:
    """Convert bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes < 1024:
            return f"{bytes:.2f} {unit}"
        bytes /= 1024
    return f"{bytes:.2f} PB"