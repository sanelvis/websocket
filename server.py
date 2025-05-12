import websockets
import asyncio
import json
import hashlib
import os
import datetime
import asyncpg
import collections
from cryptography.fernet import Fernet

DATABASE_URL = os.environ["DATABASE_URL"]
FERNET_KEY = os.environ["FERNET_KEY"].encode()
cipher     = Fernet(FERNET_KEY)
pool: asyncpg.Pool
PORT = int(os.environ.get("PORT", 443))
connected_clients = set()
client_to_user = {}
file_transfer_target = {} 
client_state = {} 
client_temp = {}
login_failure = {}
RATE_LIMIT = 5
RATE_LIMIT_TIME = 20
MAX_FAIL = 5
BLOCK_TIME = 60
LOG_FOLDER = "serverlogs"
LOG_FILE = os.path.join(LOG_FOLDER, f"server_chat_log_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
user_message_times: dict[str, collections.deque[datetime.datetime]] = {}
if not os.path.exists(LOG_FOLDER):
    os.makedirs(LOG_FOLDER)

async def log_to_db(username: str | None, message: str):
    token = cipher.encrypt(message.encode("utf-8")).decode("utf-8")
    await pool.execute(
        "INSERT INTO chat_logs(username, message) VALUES($1, $2)",
        username, token
    )
    
def log_message(message: str, username: str | None = None):
    ts = datetime.datetime.utcnow().strftime("[%Y-%m-%d %H:%M:%S]")
    token = cipher.encrypt(message.encode("utf-8")).decode("utf-8")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{ts} {token}\n")

    asyncio.create_task(log_to_db(username, message))

async def get_password_hash(username: str) -> str | None:
    row = await pool.fetchrow(
        "SELECT password_hash FROM users WHERE username=$1",
        username
    )
    return row["password_hash"] if row else None

async def register_user(username: str, password_hash: str):
    await pool.execute(
        "INSERT INTO users(username, password_hash) VALUES($1, $2)",
        username, password_hash
    )
        
def hash_pass(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def sanitize(message: str) -> str:
    return message.strip().replace("\n","").replace("<","").replace(">","").replace("(","").replace(")","")

async def broadcast_online_users():
    for ws in connected_clients:
        user_list = [
            uname for client_ws, uname in client_to_user.items()
            if client_ws is not ws
        ]
        msg = json.dumps({"online_users": user_list})
        try:
            await ws.send(msg)
        except Exception as e:
            log_message(f"Error sending online users to {client_to_user.get(ws)}: {e}", None)

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
            log_message("Client unresponsive, disconnecting...", None)
            connected_clients.discard(client)
            username = client_to_user.pop(client, None)
            if username:
                log_message(f"User logged out due to heartbeat failure: {username}", username)
            client_state.pop(client, None)
            client_temp.pop(client, None)
            await broadcast_online_users()
            await client.close()

            
async def messaging(websocket): 
    print("A client connected")
    log_message("A client connected", None)
    connected_clients.add(websocket)
    await websocket.send("Enter 'R' to register or 'L' to login:")
    try:
        async for message in websocket:
            if isinstance(message, str):
                try:
                    payload = json.loads(message)
                    t       = payload.get("type")
                    tgt     = payload.get("target")
                    if t in ("typing", "stop_typing") and tgt:
                        sender = client_to_user.get(websocket)
                        for ws2, uname in client_to_user.items():
                            if uname == tgt:
                                await ws2.send(json.dumps({t: sender}))
                        continue 
                except json.JSONDecodeError:
                    pass
            key = client_to_user.get(websocket, websocket)
            dq  = user_message_times.setdefault(key, collections.deque())

            now = datetime.datetime.utcnow()
            window_start = now - datetime.timedelta(seconds=RATE_LIMIT_TIME)
            while dq and dq[0] < window_start:
                dq.popleft()

            if len(dq) >= RATE_LIMIT:
                await websocket.send(
                    "Error: You are doing that too fast. Please wait a bit."
                )
                continue
            dq.append(now)
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
                        forbidden_characters = r"([\/:;])&'`"
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
                            await websocket.send("Error: Password must not include any forbidden characters ([\"/:;])&'` . Enter a new password:")
                            continue
                        data = client_temp.get(websocket, {})
                        username = data.get("username")
                        existing = await get_password_hash(username)
                        if existing is not None:
                            await websocket.send("Error: User already taken.")
                        else:
                            pw_hash = hash_pass(password)
                            await register_user(username, pw_hash)
                            await websocket.send("Registration Successful")
                            client_to_user[websocket] = username
                            await websocket.send(f"Logged in as {username}")
                            await broadcast_online_users()
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
                        real_hash = await get_password_hash(username)
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
                        if real_hash is None or real_hash != hash_pass(password):
                            attempts, _ = login_failure[username]
                            login_failure[username] = (attempts + 1, now)
                            attempts_left = MAX_FAIL - attempts
                            await websocket.send(
                                f"Error: Invalid credentials. {attempts_left} attempts left.\n"
                                "If username is incorrect, type 'B' to re-enter it."
                            )
                            continue
                        login_failure.pop(username, None)
                        client_to_user[websocket] = username
                        await websocket.send(f"Logged in as {username}")
                        log_message(f"User logged in: {username}", username)
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
                    if data.get("type") == "typing" and data.get("target"):
                        sender = client_to_user.get(websocket)
                        for ws2, uname in client_to_user.items():
                            if uname == data["target"]:
                                await ws2.send(json.dumps({"typing": sender}))
                        continue
                    if data.get("type") == "stop_typing" and data.get("target"):
                        sender = client_to_user.get(websocket)
                        for ws2, uname in client_to_user.items():
                            if uname == data["target"]:
                                await ws2.send(json.dumps({"stop_typing": sender}))
                        continue
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
                            log_message(f"{sender} -> {target_username}: {chat_message}", sender)
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
                            sender = client_to_user.get(websocket)
                            log_message(f"{sender} started file transfer to {target_username}: {filename}", sender)
                        elif action == "end":
                            end = file_transfer_target.pop(websocket, None)
                            if end:
                                await end.send(json.dumps({"file_transfer": "end"}))
                                sender = client_to_user.get(websocket)
                                log_message(f"{sender} completed file transfer to {target_username}: {filename}", sender)        
                        continue  
                    
                except json.JSONDecodeError:
                    pass
            elif isinstance(message, bytes):
                target_socket = file_transfer_target.get(websocket)
                if target_socket:
                    await target_socket.send(message)

    except websockets.exceptions.ConnectionClosedError:
        print("Client disconnected unexpectedly.")
        log_message("Client disconnected unexpectedly.", None)
    finally:
        connected_clients.remove(websocket)
        if websocket in client_to_user:
            username = client_to_user.pop(websocket)
            log_message(f"User logged out: {username}", username)
            await broadcast_online_users()
        client_state.pop(websocket, None)
        client_temp.pop(websocket, None)
        await websocket.close()

async def main():
    global pool
    pool = await asyncpg.create_pool(DATABASE_URL)
    await pool.execute("""
      CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL
      )
    """)
    await pool.execute("""
      CREATE TABLE IF NOT EXISTS chat_logs (
        id SERIAL PRIMARY KEY,
        ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        username TEXT,
        message  TEXT NOT NULL
      )
    """)
    server = await websockets.serve(messaging, "0.0.0.0", PORT, ping_interval=30, ping_timeout=10)
    asyncio.create_task(heartbeat())
    print(f"WebSocket server started on wss://0.0.0.0:{PORT}")
    await server.wait_closed()

if __name__ == "__main__":
    asyncio.run(main())
