from boto3.dynamodb.conditions import Key
from app.db import get_user_table


def get_user_by_email(email: str):
    table = get_user_table()
    response = table.get_item(Key={"email": email})
    return response.get("Item")


def create_user(email: str, name: str, hashed_password: str):
    table = get_user_table()
    table.put_item(Item={"email": email, "name": name, "password": hashed_password})
