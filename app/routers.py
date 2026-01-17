from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from typing import List

from .database import get_db
from . import models, schemas, auth
from .auth import get_current_user

router = APIRouter()


# =========================
# AUTH ROUTES
# =========================

@router.post("/signup", status_code=status.HTTP_201_CREATED)
def signup(
    user: schemas.UserCreate,
    db: Session = Depends(get_db),
):
    existing_user = (
        db.query(models.User)
        .filter(models.User.email == user.email)
        .first()
    )

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )

    hashed_password = auth.hash_password(user.password)

    new_user = models.User(
        email=user.email,
        password=hashed_password,
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"message": "User created successfully"}


@router.post("/login")
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    user = (
        db.query(models.User)
        .filter(models.User.email == form_data.username)
        .first()
    )

    if not user or not auth.verify_password(
        form_data.password, user.password
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    access_token = auth.create_access_token(
        data={"user_id": user.id}
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
    }


# =========================
# HABIT ROUTES
# =========================

@router.post(
    "/habits",
    response_model=schemas.HabitOut,
    status_code=status.HTTP_201_CREATED,
)
def create_habit(
    habit: schemas.HabitCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    new_habit = models.Habit(
        name=habit.name,
        user_id=current_user.id,
    )

    db.add(new_habit)
    db.commit()
    db.refresh(new_habit)

    return new_habit


@router.get(
    "/habits",
    response_model=List[schemas.HabitOut],
)
def get_habits(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    habits = (
        db.query(models.Habit)
        .filter(models.Habit.user_id == current_user.id)
        .all()
    )

    return habits


@router.get(
    "/habits/{habit_id}",
    response_model=schemas.HabitOut,
)
def get_habit(
    habit_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    habit = (
        db.query(models.Habit)
        .filter(models.Habit.id == habit_id)
        .first()
    )

    if habit is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Habit not found",
        )

    if habit.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this habit",
        )

    return habit

@router.put(
    "/habits/{habit_id}",
    response_model=schemas.HabitOut,
)
def update_habit(
    habit_id: int,
    habit_update: schemas.HabitCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    habit = (
        db.query(models.Habit)
        .filter(models.Habit.id == habit_id)
        .first()
    )

    if habit is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Habit not found",
        )

    if habit.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update this habit",
        )

    habit.name = habit_update.name
    db.commit()
    db.refresh(habit)

    return habit

@router.delete(
    "/habits/{habit_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_habit(
    habit_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    habit = (
        db.query(models.Habit)
        .filter(models.Habit.id == habit_id)
        .first()
    )

    if habit is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Habit not found",
        )

    if habit.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to delete this habit",
        )

    db.delete(habit)
    db.commit()
