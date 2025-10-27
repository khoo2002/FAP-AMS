import os
from fastapi import FastAPI, Request
from fastapi import Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from app.db import init_db, SessionLocal
from app.routes import auth_routes, user_routes, misc_routes
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

app = FastAPI(title="Simple Auth Service")


@app.on_event("startup")
async def startup_event():
    init_db(os.environ.get("DATABASE_URL"))


# configure CORS
allowed = os.environ.get('ALLOWED_ORIGINS', '')
if allowed:
    origins = [o.strip() for o in allowed.split(',') if o.strip()]
else:
    origins = []

if origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["*"],
    )


# basic security headers
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    # CSP: allow self for admin UI; can be adjusted via env later
    response.headers.setdefault("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; object-src 'none'")
    return response


app.include_router(auth_routes.router, prefix="/auth")
app.include_router(user_routes.router, prefix="/users")
app.include_router(misc_routes.router)

# mount login page
static_login = Path(__file__).resolve().parent / "static" / "login"
if static_login.exists():
    app.mount("/login", StaticFiles(directory=str(static_login), html=True), name="login")

# mount admin static SPA
static_admin = Path(__file__).resolve().parent / "static" / "admin"
if static_admin.exists():
    app.mount("/admin", StaticFiles(directory=str(static_admin), html=True), name="admin")

# mount reset page
static_reset = Path(__file__).resolve().parent / "static" / "reset"
if static_reset.exists():
    app.mount("/auth/password-reset", StaticFiles(directory=str(static_reset), html=True), name="password-reset")


# Prometheus metrics (basic)
REQUEST_COUNT = Counter(
    'http_requests_total', 'Total HTTP requests', ['method', 'path', 'status']
)
REQUEST_LATENCY = Histogram(
    'http_request_duration_seconds', 'HTTP request latency', ['method', 'path']
)

@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    from time import perf_counter
    start = perf_counter()
    response = await call_next(request)
    duration = perf_counter() - start
    path = request.url.path
    method = request.method
    try:
        REQUEST_COUNT.labels(method=method, path=path, status=str(response.status_code)).inc()
        REQUEST_LATENCY.labels(method=method, path=path).observe(duration)
    except Exception:
        pass
    return response

@app.get('/metrics')
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
