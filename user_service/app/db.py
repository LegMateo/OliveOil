import boto3

# Connect to DynamoDB (Local)
dynamodb = boto3.resource(
    "dynamodb",
    endpoint_url="http://localhost:8000",  # This works for local setup
    region_name="eu-central-1",
    aws_access_key_id="fakeMyKeyId",
    aws_secret_access_key="fakeSecretAccessKey",
)


def get_user_table():
    return dynamodb.Table("users")
