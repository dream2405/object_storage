from pydantic import BaseModel, ConfigDict
from datetime import datetime
import uuid


class PublicUser(BaseModel):
    name: str


class SignInUser(PublicUser):
    password: str


class PrivateUser(PublicUser):
    hash: str

class CreateObject(BaseModel):
    permission: str
    password: str

class PublicObject(BaseModel):
    id: uuid.UUID
    created_at: datetime
    size: float
    permission: str
    user_id: str
    model_config = ConfigDict(from_attributes=True)