from fastapi import APIRouter, HTTPException, Response, Request, Query

from app.models import (
    RegisterRequest,
    AuthResponse,
    LoginRequest,
    TokenRefreshResponse,
)
from app.auth import (
    hash_password,
    send_verification_email,
    verify_verification_token,
    verify_password,
    create_access_token,
    create_refresh_token,
    verify_refresh_token,
)
from app.user_repository import (
    get_user_by_email,
    create_user,
    has_mx_record,
    normalize_email,
    mark_user_as_verified,
)

router = APIRouter()


@router.post("/register", response_model=AuthResponse)
def register_user(request: RegisterRequest):
    domain = request.email.split("@")[1]
    if not has_mx_record(domain):
        raise HTTPException(status_code=400, detail="Invalid email domain")
    normalized_email = normalize_email(request.email)
    existing_user = get_user_by_email(normalized_email)
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")

    hashed = hash_password(request.password)
    create_user(
        normalized_email,
        request.name,
        hashed,
    )
    send_verification_email(request.email)

    return {"message": "User registered successfully"}


@router.post("/login", response_model=AuthResponse)
async def login_user(request: LoginRequest, response: Response):
    normalized_email = normalize_email(request.email)
    existing_user = get_user_by_email(normalized_email)
    dummy_hash = "$2b$12$C5NRDqb2g19T7UmebqMGCuwtvEIC5Wxa2c.ywqZJjJG3lysvW48JK"  # Dummy hash za timing attacks
    hashed_password = existing_user.get("password") if existing_user else dummy_hash
    is_password_valid = verify_password(request.password, hashed_password)

    if not existing_user or not is_password_valid:
        raise HTTPException(status_code=400, detail="Wrong e-mail or password")

    if not existing_user["is_verified"]:
        raise HTTPException(status_code=403, detail="E-mail is not verified")

    access_token = create_access_token(data={"sub": normalized_email})
    refresh_token = create_refresh_token(data={"sub": normalized_email})

    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=True,
        samesite="Lax",
        max_age=900,
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="Lax",
        max_age=259200,
    )

    return {"message": "User successfully logged in"}


@router.post("/refresh-token", response_model=TokenRefreshResponse)
def refresh_token(request: Request, response: Response):
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Missing refresh token")

    try:
        payload = verify_refresh_token(refresh_token)
        user_email = payload.get("sub")
        if not user_email:
            raise HTTPException(status_code=401, detail="Invalid token")

        new_access_token = create_access_token({"sub": user_email})

        response.set_cookie(
            key="access_token",
            value=new_access_token,
            httponly=True,
            secure=True,
            samesite="Lax",
            max_age=900,
        )

        return {"access_token": new_access_token}

    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")


@router.post("/logout")
def logout(request: Request, response: Response):
    try:
        response.delete_cookie("access_token")
        response.delete_cookie("refresh_token")
        return {"message": "Logged out successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Logout failed: {str(e)}")


@router.get("/verify-email")
def verify_email(token: str = Query(...)):
    try:
        email = verify_verification_token(token)
        user = get_user_by_email(email)

        if user.get("is_verified"):
            return {"message": f"Email {email} is already verified"}

        mark_user_as_verified(email)
        return {"message": f"Email {email} verified successfully"}

    except ValueError:
        raise HTTPException(
            status_code=400, detail="Invalid or expired verification token"
        )
