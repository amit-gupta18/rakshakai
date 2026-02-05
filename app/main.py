"""
RakshakAI - Main FastAPI Application
An agentic honeypot system for detecting and analyzing security threats.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import config
from app.models.schemas import HealthCheckResponse
from app.routes import honeypot

# Validate configuration on startup
try:
    config.validate()
except ValueError as e:
    print(f"⚠️  Configuration Error: {e}")
    print("Please set the required environment variables in your .env file")

# Initialize FastAPI app
app = FastAPI(
    title=config.APP_NAME,
    version=config.APP_VERSION,
    description="Agentic honeypot system for security threat detection and analysis",
    docs_url="/docs",  # Swagger UI available at /docs
    redoc_url="/redoc"  # ReDoc available at /redoc
)

# Configure CORS (adjust for production as needed)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify allowed origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(honeypot.router)

# Include new PRD-style API router
from app.routes import honeypot_api
app.include_router(honeypot_api.router)


# Health check endpoint (no authentication required)
@app.get("/", response_model=HealthCheckResponse, tags=["health"])
async def health_check():
    """
    Health check endpoint to verify the service is running.
    
    Returns:
        Status information about the service
    """
    return HealthCheckResponse(
        status="healthy",
        app=config.APP_NAME,
        version=config.APP_VERSION
    )


# Startup event
@app.on_event("startup")
async def startup_event():
    """Actions to perform on application startup"""
    print(f"🚀 Starting {config.APP_NAME} v{config.APP_VERSION}")
    print(f"📝 API Documentation available at http://{config.HOST}:{config.PORT}/docs")


# Shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    """Actions to perform on application shutdown"""
    print(f"👋 Shutting down {config.APP_NAME}")


# Entry point for running with uvicorn
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=config.HOST,
        port=config.PORT,
        reload=config.DEBUG
    )
