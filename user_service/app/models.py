from pydantic import BaseModel, EmailStr, field_validator
import re


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    name: str

    @field_validator("password")
    @staticmethod
    def validate_password_strength(value: str):
        if (
            len(value) < 8
            or not re.search(r"[A-Z]", value)
            or not re.search(r"\d", value)
        ):
            raise ValueError(
                "Password must be at least 8 characters long, include an uppercase letter and a number."
            )
        return value


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class AuthResponse(BaseModel):
    message: str


class TokenRefreshRequest(BaseModel):
    refresh_token: str


class TokenRefreshResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
