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


def create_user(
    email: str,
    name: str,
    hashed_password: str | None = None,
    is_verified: bool = False,
    auth_provider: str = "local",
):
    table = get_user_table()
    item = {
        "email": email,
        "name": name,
        "is_verified": is_verified,
        "auth_provider": auth_provider,
    }

    if hashed_password:  # only add password if it’s not None
        item["password"] = hashed_password

    table.put_item(Item=item)


def mark_user_as_verified(email: str):
    table = get_user_table()
    table.update_item(
        Key={"email": email},
        UpdateExpression="SET is_verified = :val",
        ExpressionAttributeValues={":val": True},
    )
