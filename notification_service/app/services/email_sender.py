import boto3
import os

AWS_REGION = os.getenv("AWS_REGION")
EMAIL_SOURCE = os.getenv("EMAIL_SOURCE")

import boto3
import os
import asyncio

AWS_REGION = os.getenv("AWS_REGION")
EMAIL_SOURCE = os.getenv("EMAIL_SOURCE")


async def send_email(to_email: str, subject: str, body: str):
    # boto3 is not async, so we use a thread executor
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, lambda: _send(to_email, subject, body))


def _send(to_email: str, subject: str, body: str):
    client = boto3.client("ses", region_name=AWS_REGION)
    client.send_email(
        Source=EMAIL_SOURCE,
        Destination={"ToAddresses": [to_email]},
        Message={
            "Subject": {"Data": subject},
            "Body": {"Text": {"Data": body}},
        },
    )
