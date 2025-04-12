import re
from fastapi import APIRouter, HTTPException, Response, Request, Query
from fastapi.responses import RedirectResponse
from starlette.datastructures import URL
import aiohttp
import secrets
import os
import asyncio

from app.db import get_user_table

from app.models import (
    RegisterRequest,
    AuthResponse,
    LoginRequest,
    TokenRefreshResponse,
    ForgotPasswordRequest,
    ResetPasswordRequest,
)
from app.auth import (
    hash_password,
    notify_email_verification,
    verify_verification_token,
    verify_password,
    create_access_token,
    create_refresh_token,
    verify_refresh_token,
    set_auth_cookies,
    create_password_reset_token,
    create_verification_token,
    verify_password_reset_token,
)
from app.user_repository import (
    get_user_by_email,
    create_user,
    has_mx_record,
    normalize_email,
    mark_user_as_verified,
)

router = APIRouter()

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")
AUTH_SERVICE_URL = os.getenv("AUTH_SERVICE_URL")
FRONTEND_SUCCESS_URL = os.getenv("FRONTEND_SUCCESS_URL")


@router.post("/register", response_model=AuthResponse)
async def register_user(request: RegisterRequest):
    domain = request.email.split("@")[1]
    if not has_mx_record(domain):
        raise HTTPException(status_code=400, detail="Invalid email domain")
    normalized_email = normalize_email(request.email)
    existing_user = get_user_by_email(normalized_email)

    if existing_user:
        raise HTTPException(status_code=400, detail="Registration failed")
    if (
        len(request.password) < 8
        or not re.search(r"[A-Z]", request.password)
        or not re.search(r"\d", request.password)
    ):
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 8 characters long, include an uppercase letter and a number.",
        )

    hashed = hash_password(request.password)
    create_user(
        normalized_email,
        request.name,
        hashed,
    )
    token = create_verification_token(request.email)
    verification_link = f"{AUTH_SERVICE_URL}/auth/verify-email?token={token}"

    await notify_email_verification(
        request.email, verification_link, type="account-verify"
    )

    return {"message": "User registered successfully"}


@router.post("/login", response_model=AuthResponse)
async def login_user(request: LoginRequest, response: Response):
    normalized_email = normalize_email(request.email)
    existing_user = get_user_by_email(normalized_email)
    dummy_hash = "$2b$12$C5NRDqb2g19T7UmebqMGCuwtvEIC5Wxa2c.ywqZJjJG3lysvW48JK"  # Dummy hash za timing attacks
    hashed_password = existing_user.get("password") if existing_user else dummy_hash
    is_password_valid = verify_password(request.password, hashed_password)

    if existing_user.get("auth_provider") == "google":
        raise HTTPException(
            status_code=400,
            detail="Login failed. Please check your credentials or try another method.",
        )
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
def logout(response: Response):
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
            return {"message": "If the account exists, a verification email was sent."}

        mark_user_as_verified(email)
        return {"message": "The account is successfully verified"}
    except ValueError:
        raise HTTPException(
            status_code=400, detail="Invalid or expired verification token"
        )


@router.post("/resend-verification")
async def resend_verification_email(request: ForgotPasswordRequest):
    normalized_email = normalize_email(request.email)
    user = get_user_by_email(normalized_email)

    if not user or user.get("is_verified") or user.get("auth_provider") == "google":
        return {"message": "If the account exists, a verification email was sent."}

    token = create_verification_token(request.email)
    verification_link = f"{AUTH_SERVICE_URL}/auth/verify-email?token={token}"

    await notify_email_verification(
        request.email, verification_link, type="account-verify"
    )

    return {"message": "If the account exists, a verification email was sent."}


@router.post("/forgot-password")
async def forgot_password(request: ForgotPasswordRequest):
    domain = request.email.split("@")[1]

    if not has_mx_record(domain):
        raise HTTPException(status_code=400, detail="Invalid email domain")

    normalized_email = normalize_email(request.email)
    user = get_user_by_email(normalized_email)

    if not user or user.get("auth_provider") == "google":
        return {"message": "If that email exists, a reset link has been sent."}

    token = create_password_reset_token(normalized_email)
    reset_link = f"{AUTH_SERVICE_URL}/auth/reset-password?token={token}"

    await notify_email_verification(request.email, reset_link, type="password-reset")

    return {"message": "If that email exists, a reset link has been sent."}


@router.post("/reset-password")
def reset_password(request: ResetPasswordRequest):
    try:

        email = verify_password_reset_token(request.token)
        user = get_user_by_email(email)

        if not user.get("is_verified"):
            raise HTTPException(
                status_code=403,
                detail="E-mail must be verified before resetting password",
            )
        if request.new_password != request.confirm_password:
            raise HTTPException(status_code=400, detail="Passwords do not match")

        if (
            len(request.new_password) < 8
            or not re.search(r"[A-Z]", request.new_password)
            or not re.search(r"\d", request.new_password)
        ):
            raise HTTPException(
                status_code=400,
                detail="Password must be at least 8 characters long, include an uppercase letter and a number.",
            )

        if not user or user.get("auth_provider") == "google":
            raise HTTPException(status_code=400, detail="Invalid token or user")

        hashed = hash_password(request.new_password)

        table = get_user_table()
        table.update_item(
            Key={"email": email},
            UpdateExpression="SET password = :pwd",
            ExpressionAttributeValues={":pwd": hashed},
        )

        return {"message": "Password successfully reset"}

    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid or expired token")


# GOOGLE
@router.get("/google/login")
async def google_login(response: Response):
    state = secrets.token_urlsafe(16)
    response.set_cookie("oauth_state", state, httponly=True)

    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "response_type": "code",
        "scope": "openid email profile",
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "access_type": "offline",
        "prompt": "consent",
    }

    url = URL("https://accounts.google.com/o/oauth2/v2/auth").include_query_params(
        **params
    )
    return RedirectResponse(str(url))


@router.get("/google/callback")
async def google_callback(request: Request):
    state_from_google = request.query_params.get("state")
    expected_state = request.cookies.get("oauth_state")
    code = request.query_params.get("code")

    if state_from_google != expected_state:
        raise HTTPException(status_code=400, detail="Invalid state token")

    if not code:
        raise HTTPException(status_code=400, detail="Missing code in callback")

    token_url = "https://oauth2.googleapis.com/token"
    data = {
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code",
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(token_url, data=data) as resp:
            if resp.status != 200:
                raise HTTPException(
                    status_code=resp.status, detail="Token request failed"
                )
            tokens = await resp.json()

        access_token = tokens.get("access_token")
        if not access_token:
            raise HTTPException(status_code=400, detail="Missing access token")

        async with session.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        ) as userinfo_resp:
            if userinfo_resp.status != 200:
                raise HTTPException(
                    status_code=userinfo_resp.status, detail="Failed to fetch user info"
                )

            user_info = await userinfo_resp.json()

    google_email = normalize_email(user_info.get("email"))
    if not user_info.get("verified_email"):
        raise HTTPException(status_code=400, detail="Google account email not verified")
    existing_user = get_user_by_email(google_email)

    if existing_user:
        if existing_user.get("auth_provider") != "google":
            raise HTTPException(
                status_code=400,
                detail="Login failed. Please check your credentials or try another method.",
            )
        else:
            access_token = create_access_token(data={"sub": google_email})
            refresh_token = create_refresh_token(data={"sub": google_email})

            response = RedirectResponse(
                url=FRONTEND_SUCCESS_URL
            )  # Change with frontend route
            set_auth_cookies(response, access_token, refresh_token)

            return response
    else:

        create_user(
            email=google_email,
            name=user_info.get("name"),
            hashed_password="",
            is_verified=True,
            auth_provider="google",
        )

        access_token = create_access_token(data={"sub": google_email})
        refresh_token = create_refresh_token(data={"sub": google_email})

        response = RedirectResponse(
            url=FRONTEND_SUCCESS_URL
        )  # Change with frontend route

        set_auth_cookies(response, access_token, refresh_token)

        return response


@router.get("/success")
def success_page():
    return {"message": "Google login successful. Cookies should now be set."}
