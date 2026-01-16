from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordRequestForm
from typing import List

from fastapi import Depends
from jose import JWTError, jwt
import os
from .database import get_db
from . import models, schemas, auth
from fastapi.security import OAuth2PasswordBearer
from .auth import get_current_user

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(
            token,
            os.getenv("SECRET_KEY"),
            algorithms=[os.getenv("ALGORITHM")]
        )

        user_id = payload.get("user_id")

        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")

        return user_id

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

router = APIRouter()


@router.post("/signup")
def signup(user: schemas.UserCreate, db: Session = Depends(get_db)):
    existing_user = (
        db.query(models.User)
        .filter(models.User.email == user.email)
        .first()
    )

    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = auth.hash_password(user.password)
    new_user = models.User(email=user.email, password=hashed_password)

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"message": "User created successfully"}

@router.post("/login")
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    user = db.query(models.User).filter(
        models.User.email == form_data.username
    ).first()

    if not user:
        raise HTTPException(status_code=400, detail="Invalid credentials")

    if not auth.verify_password(form_data.password, user.password):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    access_token = auth.create_access_token(
        data={"user_id": user.id}
    )
    return {
        "access_token": access_token,
        "token_type": "bearer"
    }

@router.post("/habits", response_model=schemas.HabitResponse)
def create_habit(
    habit: schemas.HabitCreate,
    db: Session = Depends(get_db),
    user_id: int = Depends(get_current_user)
):
    new_habit = models.Habit(
        name=habit.name,
        user_id=user_id
    )

    db.add(new_habit)
    db.commit()
    db.refresh(new_habit)

    return new_habit

@router.get("/habits", response_model=list[schemas.HabitResponse])
def get_habits(
    db: Session = Depends(get_db),
    user_id: int = Depends(get_current_user)
):
    habits = (
        db.query(models.Habit)
        .filter(models.Habit.user_id == user_id)
        .all()
    )

    return habits
