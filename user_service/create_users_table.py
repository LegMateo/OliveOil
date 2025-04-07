import boto3

# Connect to DynamoDB Local
dynamodb = boto3.resource(
    "dynamodb",
    endpoint_url="http://localhost:8000",
    region_name="eu-central-1",
    aws_access_key_id="fakeMyKeyId",
    aws_secret_access_key="fakeSecretAccessKey",
)

# Create table if not exists
table_name = "users"
existing_tables = dynamodb.meta.client.list_tables()["TableNames"]

if table_name not in existing_tables:
    print(f"Creating table '{table_name}'...")

    table = dynamodb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "email", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "email", "AttributeType": "S"}],
        ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
    )
