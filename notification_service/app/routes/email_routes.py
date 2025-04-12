from fastapi import APIRouter, HTTPException
from app.services.email_sender import send_email
from app.models import VerifyEmailRequest

router = APIRouter()


@router.post("/verify-email")
async def handle_verification_email(req: VerifyEmailRequest):
    subjects = {
        "account-verify": "Verify your email address",
        "password-reset": "Change password",
    }
    bodies = {
        "account-verify": "Click the link below to verify your email address:\n\n",
        "password-reset": "Click the link below to reset your password:\n\n",
    }

    if req.type not in subjects:
        raise HTTPException(status_code=400, detail="Invalid email type")

    subject = subjects[req.type]
    body_text = bodies[req.type] + req.link
    await send_email(req.email, subject, body_text)
    return {"message": "Email sent"}
