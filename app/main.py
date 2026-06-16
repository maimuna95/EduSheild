from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, RedirectResponse
from app.routers import scanner_router
from app.database import init_db

app = FastAPI(
    title="EduShield API",
    description="Cybersecurity Monitoring System for Australian Educational Institutions",
    version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_no_cache_header(request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return response


app.include_router(scanner_router.router, prefix="/api/v1", tags=["Scanner"])

# Mount frontend static files
app.mount("/static", StaticFiles(directory="frontend/static"), name="static")


@app.get("/dashboard", response_class=FileResponse, tags=["Frontend"])
async def dashboard():
    """Serve the main frontend dashboard."""
    return "frontend/index.html"


@app.on_event("startup")
async def startup():
    await init_db()


@app.get("/")
async def root():
    """Redirect root to the frontend dashboard."""
    return RedirectResponse(url="/dashboard")


@app.get("/api/health", tags=["System"])
async def health_check():
    """API health check endpoint."""
    return {"message": "EduShield API is running", "status": "online"}
