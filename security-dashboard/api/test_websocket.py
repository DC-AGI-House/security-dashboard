import asyncio
import websockets
import json

async def test_websocket():
    uri = "ws://localhost:8000/ws"
    async with websockets.connect(uri) as websocket:
        print("Connected to WebSocket")
        try:
            while True:
                response = await websocket.recv()
                data = json.loads(response)
                print(f"Received data: {json.dumps(data, indent=2)}")
        except websockets.exceptions.ConnectionClosed:
            print("Connection closed")

# Run the test
asyncio.get_event_loop().run_until_complete(test_websocket())