from pydantic import BaseModel


class EmailRequest(BaseModel):
    to_address: str
    subject: str
    body_text: str


class VerifyEmailRequest(BaseModel):
    email: str
    link: str
    type: str
