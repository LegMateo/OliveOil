from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError
import boto3

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password, hashed_password):
    return pwd_context.verify(password, hashed_password)


SECRET_KEY = "your_secret_key"
JWT_SECRET = "supersecret"
ALGORITHM = "HS256"
EMAIL_VERIFICATION_EXPIRE_MINUTES = 20
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_MINUTES = 4320


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


def send_verification_email(email: str):
    token = create_verification_token(email)
    verification_link = f"http://localhost:8002/auth/verify-email?token={token}"

    ses = boto3.client("ses", region_name="eu-central-1")
    ses.send_email(
        Source="no-reply@opg-gheda.com",
        Destination={"ToAddresses": [email]},
        Message={
            "Subject": {"Data": "Verify your email address"},
            "Body": {
                "Text": {
                    "Data": f"Click the link to verify your email:\n{verification_link}"
                }
            },
        },
    )
