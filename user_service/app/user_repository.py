from boto3.dynamodb.conditions import Key
from fastapi import HTTPException
from app.db import get_user_table
import dns.resolver
from functools import lru_cache


@lru_cache(maxsize=100)
def has_mx_record(domain: str) -> bool:
    try:
        records = dns.resolver.resolve(domain, "MX", lifetime=2)
        return len(records) > 0
    except Exception:
        return False


def normalize_email(email: str) -> str:
    local, domain = email.lower().split("@")
    if domain == "gmail.com":
        local = local.split("+")[0]  # Strip alias part
    return f"{local}@{domain}"


def get_user_by_email(email: str):
    table = get_user_table()
    response = table.get_item(Key={"email": email})
    return response.get("Item")


def create_user(email: str, name: str, hashed_password: str):
    table = get_user_table()
    table.put_item(
        Item={
            "email": email,
            "name": name,
            "password": hashed_password,
            "is_verified": False,
        }
    )


def mark_user_as_verified(email: str):
    table = get_user_table()
    table.update_item(
        Key={"email": email},
        UpdateExpression="SET is_verified = :val",
        ExpressionAttributeValues={":val": True},
    )
