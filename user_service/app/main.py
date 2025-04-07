from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI
from app.routes.user_routes import router as user_router


app = FastAPI()
app.include_router(user_router, prefix="/auth", tags=["User Auth"])
