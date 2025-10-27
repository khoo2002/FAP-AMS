from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, timedelta, timezone
import os, secrets
from app.db import get_db
from app import models, schemas, auth
from app.utils import SimpleRateLimiter, get_client_ip
from sqlalchemy import text

reset_req_limiter = SimpleRateLimiter(window_seconds=60, max_events=10)

router = APIRouter()

@router.get('/', response_model=list[schemas.UserOut])
def list_users(db: Session = Depends(get_db), token_data: dict = Depends(auth.get_current_user)):
    # require admin role to list users
    roles = token_data.get('roles', [])
    if 'admin' not in roles:
        raise HTTPException(status_code=403, detail='admin role required')
    users = db.query(models.User).all()
    out = []
    for u in users:
        out.append(schemas.UserOut(id=u.id, email=u.email, roles=[r.name for r in u.roles], created_at=u.created_at, last_login=u.last_login, is_active=u.is_active))
    return out

@router.post('/password-reset/request')
def create_password_reset_link(payload: schemas.PasswordResetCreate, db: Session = Depends(get_db), token_data: dict = Depends(auth.get_current_user)):
    # admin can create reset links for any user
    if 'admin' not in token_data.get('roles', []):
        raise HTTPException(status_code=403, detail='admin role required')
    user = db.query(models.User).filter(models.User.email == payload.email).first()
    if not user:
        raise HTTPException(status_code=404, detail='User not found')
    # rate limit by target email
    # Note: Admin-only endpoint still rate-limited to prevent abuse
    if not reset_req_limiter.allow(f"reset:{payload.email}"):
        raise HTTPException(status_code=429, detail='Too many reset requests, try later')
    # Parse expiry minutes with safe fallback when env is unset or empty
    _val = os.environ.get('PASSWORD_RESET_EXPIRES_MINUTES')
    try:
        minutes = int(_val) if (_val is not None and str(_val).strip() != '') else 30
    except Exception:
        minutes = 30
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=minutes)
    pr = models.PasswordResetToken(token=token, user_id=user.id, expires_at=expires_at)
    db.add(pr)
    db.commit()
    # allow configuring public base url to construct absolute link (useful for emails)
    public_base = os.environ.get('PUBLIC_BASE_URL', '').rstrip('/')
    path = f"/auth/password-reset?token={token}"
    if public_base:
        out = {"reset_link": path, "absolute_link": f"{public_base}{path}", "expires_at": expires_at.isoformat()}
    else:
        out = {"reset_link": path, "expires_at": expires_at.isoformat()}
    try:
        db.execute(text("INSERT INTO audit_logs(actor_user_id, action, target_email, metadata) VALUES(:id,:a,:t,to_jsonb(:m::text))"),
                   {"id": int(token_data.get('sub')), "a": "password_reset_requested", "t": payload.email, "m": token})
        db.commit()
    except Exception:
        db.rollback()
    return out

@router.post('/password-reset/use')
def use_password_reset(payload: schemas.PasswordResetUse, db: Session = Depends(get_db)):
    pr = db.query(models.PasswordResetToken).filter(models.PasswordResetToken.token == payload.token).first()
    if not pr or pr.used:
        raise HTTPException(status_code=400, detail='Invalid token')
    if pr.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail='Token expired')
    user = db.query(models.User).filter(models.User.id == pr.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail='User not found')
    ok, msg = auth.password_is_strong(payload.new_password)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    user.password_hash = auth.get_password_hash(payload.new_password)
    pr.used = True
    db.add_all([user, pr])
    db.commit()
    try:
        db.execute(text("INSERT INTO audit_logs(actor_user_id, action, target_email) VALUES(:id,:a,:t)"),
                   {"id": user.id, "a": "password_reset_used", "t": user.email})
        db.commit()
    except Exception:
        db.rollback()
    return {"status": "ok"}
