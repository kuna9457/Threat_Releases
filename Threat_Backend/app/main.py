from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from dotenv import load_dotenv

# Load environment variables from .env file into os.environ early
load_dotenv()

# Apply SSL fix for corporate proxies (Zscaler)
try:
    from app.utils.ssl_patch import apply_ssl_patch
    apply_ssl_patch()
except Exception:
    pass

from app.api.routes import router
from app.api.risk_routes import router as risk_router
from app.api.email_routes import router as email_router

app = FastAPI(title="URL Threat Intelligence Platform")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api/v1")
app.include_router(risk_router, prefix="/api/v1")
app.include_router(email_router, prefix="/api/v1")

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
