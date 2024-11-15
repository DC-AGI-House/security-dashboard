import asyncio
import websockets
import json
import requests
import time
from datetime import datetime

def test_health():
    response = requests.get('http://localhost:8000/health')
    print("\n=== Health Check ===")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")

def test_metrics():
    response = requests.get('http://localhost:8000/system-metrics')
    print("\n=== System Metrics ===")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")

async def test_websocket_connection():
    print("\n=== WebSocket Test ===")
    uri = "ws://localhost:8000/ws"
    async with websockets.connect(uri) as websocket:
        print("Connected to WebSocket")
        try:
            # Listen for 5 messages then exit
            for i in range(5):
                response = await websocket.recv()
                data = json.loads(response)
                print(f"\nMessage {i+1}:")
                print(json.dumps(data, indent=2))
                await asyncio.sleep(1)
        except websockets.exceptions.ConnectionClosed:
            print("Connection closed")

def test_battle_log():
    test_log = {
        "message": "Test alert from API test",
        "timestamp": datetime.now().isoformat(),
        "severity": "warning"
    }
    
    response = requests.post(
        'http://localhost:8000/api/battle-log',
        json=test_log
    )
    print("\n=== Battle Log Test ===")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")

async def run_tests():
    print("Starting API Tests...")
    
    # Test REST endpoints
    test_health()
    test_metrics()
    test_battle_log()
    
    # Test WebSocket
    await test_websocket_connection()
    
    print("\nTests completed!")

if __name__ == "__main__":
    # Install required packages if not already installed
    # pip install requests websockets
    
    asyncio.get_event_loop().run_until_complete(run_tests())