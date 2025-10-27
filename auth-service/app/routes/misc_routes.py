from fastapi import APIRouter, Response
from starlette.responses import JSONResponse
from sqlalchemy import text
from app import auth as auth_module
from app.db import engine
import os

router = APIRouter()


@router.get('/.well-known/public_key.pem')
def public_key():
    data = auth_module.get_public_key_pem()
    return Response(content=data, media_type='application/x-pem-file')


@router.get('/.well-known/jwks.json')
def jwks():
    return auth_module.get_jwks()


@router.get('/healthz')
def healthz():
    # basic liveness probe
    return {"status": "ok"}


@router.get('/readyz')
def readyz():
    # simple readiness probe that verifies DB connectivity
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return {"status": "ready"}
    except Exception as e:
        return JSONResponse(status_code=503, content={"status": "degraded", "error": str(e)})


@router.get('/version')
def version():
    import os
    return {"version": os.environ.get('APP_VERSION', 'dev')}


@router.get('/.well-known/openid-configuration')
def oidc_configuration():
    issuer = os.environ.get('JWT_ISSUER') or os.environ.get('PUBLIC_BASE_URL', '').rstrip('/') or ''
    base = issuer or ''
    # If we cannot determine an issuer URL, return minimal fields without URLs
    data = {
        "issuer": issuer or "",
        "jwks_uri": f"{base}/.well-known/jwks.json" if base else "",
        "authorization_endpoint": f"{base}/login" if base else "",
        "token_endpoint": f"{base}/auth/login" if base else "",
        "response_types_supported": ["token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
    }
    return data
