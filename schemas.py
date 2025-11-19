"""
Database Schemas for WhatsApp-like app

Each Pydantic model represents a collection in MongoDB. The collection name is the
lowercase of the class name (handled by our database helpers at usage time).
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List
from datetime import datetime

class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Unique email")
    mobile: str = Field(..., description="Unique mobile number in international format")
    password_hash: str = Field(..., description="BCrypt password hash")
    avatars: List[str] = Field(default_factory=list, description="List of profile picture URLs")
    status_message: Optional[str] = Field("Hey there! I am using Vibe Chat.")
    online: bool = Field(default=False)
    last_seen: Optional[datetime] = None

class Chat(BaseModel):
    # One-to-one chat between two users for MVP
    participant_ids: List[str] = Field(..., min_items=2, max_items=2, description="User IDs (as strings)")
    created_at: Optional[datetime] = None

class Message(BaseModel):
    chat_id: str = Field(..., description="Chat ID")
    sender_id: str = Field(..., description="User ID of sender")
    content: str = Field(..., description="Text content")
    sent_at: Optional[datetime] = None
    seen_by: List[str] = Field(default_factory=list, description="User IDs that have seen this message")
