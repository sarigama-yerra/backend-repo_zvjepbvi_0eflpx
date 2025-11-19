import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from bson import ObjectId

from database import db, create_document, get_documents
from schemas import User as UserSchema, Chat as ChatSchema, Message as MessageSchema

SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------ Helpers ------------

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(status_code=401, detail="Could not validate credentials")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db["user"].find_one({"_id": ObjectId(user_id)})
    if not user:
        raise credentials_exception
    return user

# ------------ Models (request/response) ------------

class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    mobile: str
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class ProfileUpdate(BaseModel):
    name: Optional[str] = None
    status_message: Optional[str] = None

class MessageCreate(BaseModel):
    chat_id: str
    content: str

# ------------ Auth & Users ------------

@app.post("/auth/register", response_model=TokenResponse)
def register(data: RegisterRequest):
    if db["user"].find_one({"email": data.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    if db["user"].find_one({"mobile": data.mobile}):
        raise HTTPException(status_code=400, detail="Mobile already registered")

    hashed = get_password_hash(data.password)
    user = UserSchema(
        name=data.name,
        email=data.email,
        mobile=data.mobile,
        password_hash=hashed,
        avatars=[],
        online=False,
        last_seen=None,
    )
    user_id = create_document("user", user)
    access_token = create_access_token({"sub": user_id})
    return TokenResponse(access_token=access_token)

@app.post("/auth/login", response_model=TokenResponse)
def login(data: LoginRequest):
    user = db["user"].find_one({"email": data.email})
    if not user or not verify_password(data.password, user.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Incorrect email or password")

    db["user"].update_one({"_id": user["_id"]}, {"$set": {"online": True}})

    token = create_access_token({"sub": str(user["_id"])})
    return TokenResponse(access_token=token)

@app.post("/auth/logout")
def logout(current=Depends(get_current_user)):
    db["user"].update_one({"_id": current["_id"]}, {"$set": {"online": False, "last_seen": datetime.now(timezone.utc)}})
    return {"ok": True}

@app.get("/me")
def me(current=Depends(get_current_user)):
    current["_id"] = str(current["_id"])  # serialize
    return current

@app.patch("/me")
def update_profile(update: ProfileUpdate, current=Depends(get_current_user)):
    update_dict = {k: v for k, v in update.model_dump().items() if v is not None}
    if update_dict:
        db["user"].update_one({"_id": current["_id"]}, {"$set": update_dict})
    return {"ok": True}

# ------------ Chats & Messages ------------

@app.post("/chats/start")
def start_chat(other_user_id: str, current=Depends(get_current_user)):
    uid = str(current["_id"]) if isinstance(current["_id"], ObjectId) else current["_id"]
    existing = db["chat"].find_one({"participant_ids": {"$all": [uid, other_user_id]}})
    if existing:
        return {"chat_id": str(existing["_id"]) }

    chat = ChatSchema(participant_ids=[uid, other_user_id])
    chat_id = create_document("chat", chat)
    return {"chat_id": chat_id}

@app.get("/chats")
def my_chats(current=Depends(get_current_user)):
    uid = str(current["_id"]) if isinstance(current["_id"], ObjectId) else current["_id"]
    chats = list(db["chat"].find({"participant_ids": uid}))
    for c in chats:
        c["_id"] = str(c["_id"])  # serialize
    return chats

@app.get("/chats/{chat_id}/messages")
def fetch_messages(chat_id: str, current=Depends(get_current_user)):
    msgs = list(db["message"].find({"chat_id": chat_id}).sort("sent_at", 1))
    for m in msgs:
        m["_id"] = str(m["_id"])  # serialize
    return msgs

@app.post("/messages")
def send_message(msg: MessageCreate, current=Depends(get_current_user)):
    uid = str(current["_id"]) if isinstance(current["_id"], ObjectId) else current["_id"]
    chat = db["chat"].find_one({"_id": ObjectId(msg.chat_id)})
    if not chat or uid not in chat.get("participant_ids", []):
        raise HTTPException(status_code=403, detail="Not a participant of this chat")

    message = MessageSchema(chat_id=msg.chat_id, sender_id=uid, content=msg.content, sent_at=datetime.now(timezone.utc))
    message_id = create_document("message", message)

    # notify via websocket
    import asyncio
    asyncio.create_task(manager.notify_chat(msg.chat_id, {
        "_id": message_id,
        "chat_id": msg.chat_id,
        "sender_id": uid,
        "content": msg.content,
        "sent_at": datetime.now(timezone.utc).isoformat(),
    }))

    return {"message_id": message_id}

# ------------ Presence & WebSockets ------------

class ConnectionManager:
    _instance = None

    @staticmethod
    def instance():
        if ConnectionManager._instance is None:
            ConnectionManager._instance = ConnectionManager()
        return ConnectionManager._instance

    def __init__(self):
        self.active_connections: dict[str, set[WebSocket]] = {}
        self.chat_rooms: dict[str, set[WebSocket]] = {}

    async def connect(self, user_id: str, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.setdefault(user_id, set()).add(websocket)
        db["user"].update_one({"_id": ObjectId(user_id)}, {"$set": {"online": True}})

    def disconnect(self, user_id: str, websocket: WebSocket):
        conns = self.active_connections.get(user_id)
        if conns and websocket in conns:
            conns.remove(websocket)
        db["user"].update_one({"_id": ObjectId(user_id)}, {"$set": {"online": False, "last_seen": datetime.now(timezone.utc)}})

    async def send_personal(self, user_id: str, message: dict):
        for ws in self.active_connections.get(user_id, set()):
            await ws.send_json(message)

    def register_chat(self, chat_id: str, websocket: WebSocket):
        self.chat_rooms.setdefault(chat_id, set()).add(websocket)

    def unregister_chat(self, chat_id: str, websocket: WebSocket):
        if chat_id in self.chat_rooms and websocket in self.chat_rooms[chat_id]:
            self.chat_rooms[chat_id].remove(websocket)

    async def notify_chat(self, chat_id: str, payload: dict):
        for ws in self.chat_rooms.get(chat_id, set()):
            await ws.send_json({"type": "message", "data": payload})


manager = ConnectionManager.instance()

@app.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: str):
    await manager.connect(user_id, websocket)
    try:
        while True:
            data = await websocket.receive_json()
            event = data.get("type")
            if event == "join_chat":
                chat_id = data.get("chat_id")
                manager.register_chat(chat_id, websocket)
            elif event == "leave_chat":
                chat_id = data.get("chat_id")
                manager.unregister_chat(chat_id, websocket)
            elif event == "typing":
                chat_id = data.get("chat_id")
                payload = {"type": "typing", "chat_id": chat_id, "user_id": user_id}
                for ws in manager.chat_rooms.get(chat_id, set()):
                    await ws.send_json(payload)
            elif event == "seen":
                msg_id = data.get("message_id")
                db["message"].update_one({"_id": ObjectId(msg_id)}, {"$addToSet": {"seen_by": user_id}})
            else:
                await websocket.send_json({"type": "error", "message": "Unknown event"})
    except WebSocketDisconnect:
        manager.disconnect(user_id, websocket)


# --------- Health & Schema ---------

@app.get("/")
def root():
    return {"message": "Chat backend running"}

@app.get("/schema")
def get_schema_names():
    return {
        "collections": [
            "user",
            "chat",
            "message"
        ]
    }
