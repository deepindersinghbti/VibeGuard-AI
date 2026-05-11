"""FastAPI main application."""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routes import scan

# Create FastAPI app
app = FastAPI(
    title="VibeGuard AI",
    description="Static Security Scanner",
    version="0.1.0",
)

# CORS middleware - for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(scan.router)


@app.get("/")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok", "service": "VibeGuard AI Backend"}
