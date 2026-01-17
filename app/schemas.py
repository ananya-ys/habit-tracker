from pydantic import BaseModel, EmailStr
from datetime import datetime


class UserCreate(BaseModel):
    email: EmailStr
    password: str


class UserLogin(BaseModel):
    email: EmailStr
    password: str

class HabitCreate(BaseModel):
    name: str

class HabitResponse(BaseModel):
    id: int
    name: str
    created_at: datetime

    class Config:
        from_attributes = True

class HabitOut(BaseModel):
    id: int
    name: str
    created_at: datetime

    class Config:
        from_attributes = True
