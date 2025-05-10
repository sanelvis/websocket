import websockets
import asyncio
import ssl
import json
import hashlib
import os
import datetime

PORT = int(os.environ.get("PORT", 443))
connected_clients = set()
client_to_user = {}
file_transfer_target = {} 
client_state = {} 
client_temp = {}
login_failure = {}
MAX_FAIL = 5
BLOCK_TIME = 60
LOG_FOLDER = "serverlogs"
LOG_FILE = os.path.join(LOG_FOLDER, f"server_chat_log_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")

if not os.path.exists(LOG_FOLDER):
    os.makedirs(LOG_FOLDER)

user_file = "user.json"

def log_message(message):
    """Append message to the log file with a timestamp."""
    with open(LOG_FILE, "a", encoding="utf-8") as log:
        timestamp = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
        log.write(f"{timestamp} {message}\n")

def load_user():
    if os.path.exists(user_file):
        with open(user_file, "r", encoding="utf-8") as f:
            user_data = json.load(f)
            return user_data
    print("No user data found.")
    return {}

def save_user(user):
    with open(user_file, "w", encoding="utf-8") as f:
        json.dump(user, f)
        
def hash_pass(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

user = load_user()

def sanitize(message: str) -> str:
    return message.strip().replace("\n","").replace("<","").replace(">","").replace("(","").replace(")","")

async def broadcast_online_users():
    online_list = list(client_to_user.values())
    message = json.dumps({"online_users": online_list})
    for client in connected_clients:
        try:
            await client.send(message)
        except Exception as e:
            log_message(f"Error sending online users list: {e}")

async def heartbeat():
    while True:
        await asyncio.sleep(30) 
        stale_clients = set()
        for client in connected_clients.copy():
            try:
                pong_waiter = await client.ping()
                await asyncio.wait_for(pong_waiter, timeout=10)
            except:
                stale_clients.add(client)

        for client in stale_clients:
            print("Client unresponsive, disconnecting...")
            log_message("Client unresponsive, disconnecting...")
            connected_clients.discard(client)
            username = client_to_user.pop(client, None)
            if username:
                log_message(f"User logged out due to heartbeat failure: {username}")
            client_state.pop(client, None)
            client_temp.pop(client, None)
            await broadcast_online_users()
            await client.close()

            
async def messaging(websocket): 
    print("A client connected")
    log_message("A client connected")
    connected_clients.add(websocket)
    
    try:
        async for message in websocket:
            if isinstance(message, str):
                if websocket in client_state:
                    state = client_state[websocket]
                    if state == "register_user":
                        username = message.strip()
                        if len(username) > 20:
                            await websocket.send("Error: Username must be at most 20 characters long. Enter a new username:")
                            continue
                        
                        client_temp[websocket] = {"action": "register", "username": username}
                        client_state[websocket] = "register_pass"
                        await websocket.send("Enter password:")
                        continue
                    elif state == "register_pass":
                        password = message.strip()
                        special_characters = "~`!@#$%^&*-_=+}{[]|,.?"
                        forbidden_characters = "([\/:;])&'`"
                        if len(password) < 8:
                            await websocket.send("Error: Password must be at least 8 characters long. Enter a new password:")
                            continue
                        if len(password) > 20:
                            await websocket.send("Error: Password must be at most 20 characters long. Enter a new password:")
                            continue
                        if not any(l.isupper() for l in password):
                            await websocket.send("Error: Password must include at least 1 uppercase character. Enter a new password:")
                            continue
                        if not any(l.islower() for l in password):
                            await websocket.send("Error: Password must include at least 1 lowercase character. Enter a new password:")
                            continue
                        if not any(l.isdigit() for l in password):
                            await websocket.send("Error: Password must include at least 1 digit. Enter a new password:")
                            continue
                        if not any(l in special_characters for l in password):
                            await websocket.send("Error: Password must include at least 1 special character. Enter a new password:")
                            continue
                        if not any(l in special_characters for l in password):
                            await websocket.send("Error: Password must include at least 1 special character. Enter a new password:")
                            continue
                        if any(l in forbidden_characters for l in password):
                            await websocket.send("Error: Password must not include any forbidden characters ([\"/:;])\&'`: . Enter a new password:")
                            continue
                        data = client_temp.get(websocket, {})
                        username = data.get("username")
                        if username is None:
                            await websocket.send("Error: Blank user.")
                        elif username in user:
                            await websocket.send("Error: User already taken.")
                        else:
                            user[username] = hash_pass(password)
                            save_user(user)
                            await websocket.send("Registration Successful")
                            log_message(f"User registered: {username}")
                        client_state.pop(websocket, None)
                        client_temp.pop(websocket, None)
                        continue
                    elif state == "login_user":
                        username = message.strip()
                        client_temp[websocket] = {"action": "login", "username": username}
                        client_state[websocket] = "login_pass"
                        await websocket.send("Enter password:")
                        continue
                    elif state == "login_pass":
                        if message.strip().upper() == "B":
                            client_state[websocket] = "login_user"
                            await websocket.send("Reenter username:")
                            continue
                        password = message.strip()
                        data = client_temp.get(websocket, {})
                        username = data.get("username")
                        now = datetime.datetime.now()
                        if username in login_failure:
                            attempts, last_time = login_failure[username]
                            time_passed = (now - last_time).total_seconds()
                            if attempts >= MAX_FAIL and time_passed < BLOCK_TIME:
                                await websocket.send("Too many failed login attempts. Try again later.")
                                continue
                            elif time_passed >= BLOCK_TIME:
                                login_failure[username] = (0,now)
                        else:
                            login_failure[username] = (0,now)
                        if username is None:
                            await websocket.send("Error: Blank User.")
                        elif username not in user or user[username] != hash_pass(password):
                            attempts, _ = login_failure[username]
                            login_failure[username] = (attempts + 1, now)
                            attempts_left = MAX_FAIL - attempts
                            await websocket.send(f"Error: Invalid credentials. {attempts_left} attempts left.\n"f"If username is incorrect, type 'B' to re-enter it.")
                            continue
                        else:
                            login_failure.pop(username, None)
                            client_to_user[websocket] = username
                            await websocket.send(f"Logged in as {username}")
                            log_message(f"User logged in: {username}")
                            await broadcast_online_users()
                            client_state.pop(websocket, None)
                            client_temp.pop(websocket, None)
                            continue
                    
                if websocket not in client_to_user:
                    if message.strip().upper() == "R":
                        client_state[websocket] = "register_user"
                        await websocket.send("Enter username:")
                        continue
                    elif message.strip().upper() == "L":
                        client_state[websocket] = "login_user"
                        await websocket.send("Enter username:")
                        continue
                    else:
                        await websocket.send("Error: You must log in or register first. Send 'L' for login or 'R' for registration.")
                        continue
                try:
                    data = json.loads(message)
                    if "target" in data and "message" in data:
                        target_username = data["target"]
                        chat_message = data["message"]
                        sender = client_to_user.get(websocket, "Unknown")
                        
                        target_socket = None
                        for client, username in client_to_user.items():
                            if username == target_username:
                                target_socket = client
                                break
                        if target_socket is None:
                            await websocket.send(json.dumps({"Error": f"User {target_username} is not online."}))
                        else:
                            await target_socket.send(json.dumps({"direct_message": f"{sender}: {chat_message}"}))
                        continue  
                    
                    if "file_transfer" in data:
                        action = data["file_transfer"]
                        target_username = data.get("target")
                        filename = data.get("filename", "unknown")

                        target_socket = None
                        for client, username in client_to_user.items():
                            if username == target_username:
                                target_socket = client
                                break

                        if not target_socket:
                            await websocket.send(json.dumps({"Error": f"User {target_username} is not online."}))
                            continue

                        if action == "start":
                            file_transfer_target[websocket] = target_socket
                            await target_socket.send(json.dumps({"file_transfer": "start","filename": filename}))
                        elif action == "end":
                            end = file_transfer_target.pop(websocket, None)
                            if end:
                                await end.send(json.dumps({"file_transfer": "end"}))
                        continue  
                    
                except json.JSONDecodeError:
                    pass

                sender = client_to_user.get(websocket, "Unknown")
                broadcast_message = f"{sender}: {message}"
                print(f"Received: {broadcast_message}")
                log_message(f"Received: {broadcast_message}")
                for client in connected_clients:
                    if client != websocket:
                        await client.send(broadcast_message)
            
            elif isinstance(message, bytes):
                target_socket = file_transfer_target.get(websocket)
                if target_socket:
                    await target_socket.send(message)

    except websockets.exceptions.ConnectionClosedError:
        print("Client disconnected unexpectedly.")
        log_message("Client disconnected unexpectedly.")
    finally:
        connected_clients.remove(websocket)
        if websocket in client_to_user:
            username = client_to_user.pop(websocket)
            log_message(f"User logged out: {username}")
            await broadcast_online_users()
        client_state.pop(websocket, None)
        client_temp.pop(websocket, None)
        await websocket.close()

async def main():
    server = await websockets.serve(messaging, "0.0.0.0", PORT, ping_interval=30, ping_timeout=10)
    asyncio.create_task(heartbeat())
    print(f"WebSocket server started on wss://0.0.0.0:{PORT}")
    await server.wait_closed()

if __name__ == "__main__":
    asyncio.run(main())
