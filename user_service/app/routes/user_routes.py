from fastapi import APIRouter, HTTPException
from app.models import RegisterRequest, RegisterResponse
from app.auth import hash_password
from app.user_repository import get_user_by_email, create_user

router = APIRouter()


@router.post("/register", response_model=RegisterResponse)
def register_user(request: RegisterRequest):
    existing_user = get_user_by_email(request.email)
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")

    hashed = hash_password(request.password)
    create_user(request.email, request.name, hashed)

    return {"message": "User registered successfully"}
