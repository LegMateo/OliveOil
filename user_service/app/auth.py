import os
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError, ExpiredSignatureError
import boto3
from fastapi import Response
import aiohttp


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password, hashed_password):
    return pwd_context.verify(password, hashed_password)


SECRET_KEY = os.getenv("SECRET_KEY")
JWT_SECRET = os.getenv("JWT_SECRET")
ALGORITHM = os.getenv("ALGORITHM")
PASSWORD_RESET_EXPIRE_MINUTES = int(os.getenv("PASSWORD_RESET_EXPIRE_MINUTES", 15))
EMAIL_VERIFICATION_EXPIRE_MINUTES = int(
    os.getenv("EMAIL_VERIFICATION_EXPIRE_MINUTES", 20)
)
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))
REFRESH_TOKEN_EXPIRE_MINUTES = int(os.getenv("REFRESH_TOKEN_EXPIRE_MINUTES", 4320))
COOKIE_DOMAIN = os.getenv("COOKIE_DOMAIN")
EMAIL_SOURCE = os.getenv("EMAIL_SOURCE")
AWS_REGION = os.getenv("AWS_REGION")


NOTIFICATION_SERVICE_URL = os.getenv(
    "NOTIFICATION_SERVICE_URL", "http://localhost:8003"
)


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=ALGORITHM)


def create_refresh_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=REFRESH_TOKEN_EXPIRE_MINUTES
    )
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=ALGORITHM)


def verify_refresh_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        if payload.get("type") != "refresh":
            raise ValueError("Invalid token type")
        return payload
    except JWTError:
        raise ValueError("Invalid or expired token")


def create_verification_token(email: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=EMAIL_VERIFICATION_EXPIRE_MINUTES
    )
    payload = {"sub": email, "exp": expire, "type": "email_verification"}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def verify_verification_token(token: str) -> str:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "email_verification":
            raise ValueError("Invalid token type")
        return payload.get("sub")  # This is the email
    except JWTError:
        raise ValueError("Invalid or expired token")


def verify_password_reset_token(token: str) -> str:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        print("Decoded payload:", payload)
        print("Token type:", payload.get("type"))
        print("Subject (email):", payload.get("sub"))
        if payload.get("type") != "password_reset":
            raise ValueError("Invalid token type")
        return payload.get("sub")
    except ExpiredSignatureError:
        raise ValueError("Token has expired")
    except JWTError:
        raise ValueError("Invalid token")


def set_auth_cookies(response: Response, access_token: str, refresh_token: str):
    response.set_cookie(
        "access_token",
        access_token,
        domain=COOKIE_DOMAIN,
        httponly=True,
        secure=True,
        samesite="Lax",
        max_age=900,
    )
    response.set_cookie(
        "refresh_token",
        refresh_token,
        domain=COOKIE_DOMAIN,
        httponly=True,
        secure=True,
        samesite="Lax",
        max_age=259200,
    )


def create_password_reset_token(email: str):
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=PASSWORD_RESET_EXPIRE_MINUTES
    )
    payload = {"sub": email, "exp": expire, "type": "password_reset"}
    return jwt.encode(payload, JWT_SECRET, algorithm=ALGORITHM)


async def notify_email_verification(email: str, link: str, type: str):
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{NOTIFICATION_SERVICE_URL}/notify/verify-email",
            json={"email": email, "link": link, "type": type},
        ) as response:
            if response.status != 200:
                text = await response.text()
                raise Exception(
                    f"Notification service error: {response.status} - {text}"
                )
