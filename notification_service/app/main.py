from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI
from app.routes import email_routes


app = FastAPI()


app.include_router(email_routes.router, prefix="/notify", tags=["Notification"])
