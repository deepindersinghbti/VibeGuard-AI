"""FastAPI main application."""
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routes import explain, scan

# Create FastAPI app
app = FastAPI(
    title="VibeGuard AI",
    description="Static Security Scanner",
    version="0.1.0",
)

def get_allowed_origins() -> list[str]:
    """
    Return allowed CORS origins for local and deployed frontends.
    
    Reads from CORS_ORIGINS environment variable (comma-separated).
    Always includes localhost origins for local development.
    
    Example:
        CORS_ORIGINS=http://localhost:3000,https://vibeguard-five.vercel.app
    """
    # Always allow localhost for local development
    origins = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
    ]

    # Add any configured origins from env var (comma-separated)
    cors_origins_env = os.getenv("CORS_ORIGINS", "").strip()
    if cors_origins_env:
        for origin in cors_origins_env.split(","):
            origin = origin.strip()
            if origin and origin not in origins:
                origins.append(origin)

    return origins


# CORS middleware - local development plus optional deployed frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_allowed_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(explain.router)
app.include_router(scan.router)


@app.get("/")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok", "service": "VibeGuard AI Backend"}


@app.get("/health")
async def health():
    """Dedicated health check endpoint for deployment monitors."""
    return {"status": "ok", "service": "VibeGuard AI backend"}
