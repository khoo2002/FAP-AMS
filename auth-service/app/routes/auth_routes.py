from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from datetime import datetime, timezone
from app.db import get_db
from app import models, schemas, auth
from app.utils import SimpleRateLimiter, get_client_ip
from sqlalchemy import text

# Naive per-IP rate limiters
login_limiter = SimpleRateLimiter(window_seconds=60, max_events=20)
reset_req_limiter = SimpleRateLimiter(window_seconds=60, max_events=10)

router = APIRouter()

# Helper to count active admins
def _count_active_admins(db: Session) -> int:
    return db.query(models.User).join(models.User.roles).filter(models.Role.name == 'admin', models.User.is_active == True).count()

@router.post('/signup', response_model=schemas.UserOut)
def signup(payload: schemas.UserCreate, db: Session = Depends(get_db)):
    existing = db.query(models.User).filter(models.User.email == payload.email).first()
    if existing:
        raise HTTPException(status_code=400, detail='Email already registered')
    ok, msg = auth.password_is_strong(payload.password)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    user = models.User(email=payload.email, password_hash=auth.get_password_hash(payload.password))
    # default role: visitor
    role = db.query(models.Role).filter(models.Role.name == 'visitor').first()
    if not role:
        role = models.Role(name='visitor', description='Default visitor role')
        db.add(role)
        db.commit()
        db.refresh(role)
    user.roles.append(role)
    db.add(user)
    db.commit()
    db.refresh(user)
    return schemas.UserOut(id=user.id, email=user.email, roles=[r.name for r in user.roles], created_at=user.created_at, last_login=user.last_login, is_active=user.is_active)

@router.post('/login', response_model=schemas.Token)
def login(payload: schemas.UserCreate, db: Session = Depends(get_db), request: Request = None):
    ip = get_client_ip(request) if request else ''
    if not login_limiter.allow(f"login:{ip}:{payload.email}"):
        raise HTTPException(status_code=429, detail='Too many attempts, please try again later')
    user = db.query(models.User).filter(models.User.email == payload.email).first()
    if not user or not auth.verify_password(payload.password, user.password_hash):
        # audit failed login
        try:
            db.execute(text("INSERT INTO audit_logs(action, target_email, ip) VALUES(:a,:t,:i)"),
                       {"a":"login_failed","t":payload.email,"i":ip})
            db.commit()
        except Exception:
            db.rollback()
        raise HTTPException(status_code=401, detail='Invalid credentials')
    if not user.is_active:
        raise HTTPException(status_code=403, detail='User is inactive')
    roles = [r.name for r in user.roles]
    token = auth.create_access_token(subject=str(user.id), roles=roles)
    # update last_login
    user.last_login = datetime.now(timezone.utc)
    db.add(user)
    db.commit()
    # audit success
    try:
        db.execute(text("INSERT INTO audit_logs(actor_user_id, actor_email, action, ip) VALUES(:id,:em,:a,:i)"),
                   {"id": user.id, "em": user.email, "a": "login_success", "i": ip})
        db.commit()
    except Exception:
        db.rollback()
    return {"access_token": token, "token_type": "bearer"}

@router.post('/assign-role')
def assign_role(payload: schemas.AssignRole, db: Session = Depends(get_db), token_data: dict = Depends(auth.get_current_user)):
    # require admin role to assign roles
    roles = token_data.get('roles', [])
    if 'admin' not in roles:
        raise HTTPException(status_code=403, detail='admin role required')
    user = db.query(models.User).filter(models.User.email == payload.email).first()
    if not user:
        raise HTTPException(status_code=404, detail='User not found')
    role = db.query(models.Role).filter(models.Role.name == payload.role).first()
    if not role:
        role = models.Role(name=payload.role)
        db.add(role)
        db.commit()
        db.refresh(role)
    if role not in user.roles:
        user.roles.append(role)
        db.add(user)
        db.commit()
    return {"status": "ok"}


@router.post('/assign-role-unassign')
def assign_or_unassign(payload: schemas.AssignRoleUnassign, db: Session = Depends(get_db), token_data: dict = Depends(auth.get_current_user)):
    if 'admin' not in token_data.get('roles', []):
        raise HTTPException(status_code=403, detail='admin role required')
    user = db.query(models.User).filter(models.User.email == payload.email).first()
    if not user:
        raise HTTPException(status_code=404, detail='User not found')
    role = db.query(models.Role).filter(models.Role.name == payload.role).first()
    if not role:
        raise HTTPException(status_code=404, detail='Role not found')
    if payload.unassign:
        # Prevent unassigning admin from the last active admin user
        if role.name == 'admin' and user.is_active:
            if _count_active_admins(db) <= 1:
                raise HTTPException(status_code=400, detail='Cannot remove admin role from the last active admin')
        if role in user.roles:
            user.roles.remove(role)
            db.add(user)
            db.commit()
        return {"status":"ok"}
    else:
        if role not in user.roles:
            user.roles.append(role)
            db.add(user)
            db.commit()
        return {"status":"ok"}


@router.post('/admin/add-user')
def admin_add_user(payload: schemas.AdminUserCreate, db: Session = Depends(get_db), token_data: dict = Depends(auth.get_current_user)):
    if 'admin' not in token_data.get('roles', []):
        raise HTTPException(status_code=403, detail='admin role required')
    existing = db.query(models.User).filter(models.User.email == payload.email).first()
    if existing:
        raise HTTPException(status_code=400, detail='Email already registered')
    ok, msg = auth.password_is_strong(payload.password)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    user = models.User(email=payload.email, password_hash=auth.get_password_hash(payload.password))
    # if no roles provided, default to visitor
    rlist = payload.roles or ['visitor']
    for rname in rlist:
        role = db.query(models.Role).filter(models.Role.name == rname).first()
        if not role:
            role = models.Role(name=rname)
            db.add(role)
            db.commit()
            db.refresh(role)
        user.roles.append(role)
    db.add(user)
    db.commit()
    try:
        db.execute(text("INSERT INTO audit_logs(actor_user_id, actor_email, action, target_email) VALUES(:id,:em,:a,:t)"),
                   {"id": int(token_data.get('sub')), "em": None, "a": "admin_add_user", "t": payload.email})
        db.commit()
    except Exception:
        db.rollback()
    db.refresh(user)
    return {"status":"ok"}


@router.post('/admin/approve-user')
def admin_approve_user(payload: schemas.ApproveUser, db: Session = Depends(get_db), token_data: dict = Depends(auth.get_current_user)):
    if 'admin' not in token_data.get('roles', []):
        raise HTTPException(status_code=403, detail='admin role required')
    user = db.query(models.User).filter(models.User.email==payload.email).first()
    if not user:
        raise HTTPException(status_code=404, detail='User not found')
    # Prevent deactivating the last active admin
    if not payload.approve:
        user_roles = [r.name for r in user.roles]
        if 'admin' in user_roles and user.is_active:
            if _count_active_admins(db) <= 1:
                raise HTTPException(status_code=400, detail='Cannot deactivate the last active admin')
    user.is_active = bool(payload.approve)
    db.add(user)
    db.commit()
    try:
        db.execute(text("INSERT INTO audit_logs(actor_user_id, action, target_email, metadata) VALUES(:id,:a,:t, to_jsonb(:m::text))"),
                   {"id": int(token_data.get('sub')), "a": "admin_approve_user", "t": payload.email, "m": str(payload.approve)})
        db.commit()
    except Exception:
        db.rollback()
    return {"status":"ok"}


@router.post('/admin/change-password')
def admin_change_password(payload: schemas.ChangePassword, db: Session = Depends(get_db), token_data: dict = Depends(auth.get_current_user)):
    if 'admin' not in token_data.get('roles', []):
        raise HTTPException(status_code=403, detail='admin role required')
    user = db.query(models.User).filter(models.User.email==payload.email).first()
    if not user:
        raise HTTPException(status_code=404, detail='User not found')
    ok, msg = auth.password_is_strong(payload.new_password)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    user.password_hash = auth.get_password_hash(payload.new_password)
    db.add(user)
    db.commit()
    try:
        db.execute(text("INSERT INTO audit_logs(actor_user_id, action, target_email) VALUES(:id,:a,:t)"),
                   {"id": int(token_data.get('sub')), "a": "admin_change_password", "t": payload.email})
        db.commit()
    except Exception:
        db.rollback()
    return {"status":"ok"}


@router.post('/change-password')
def change_password_self(payload: schemas.ChangePassword, db: Session = Depends(get_db), token_data: dict = Depends(auth.get_current_user)):
    # user can change their own password by providing current password
    user_id = int(token_data.get('sub'))
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail='User not found')
    # For self-change, require verifying current password: overload email field as identifier not used here
    # Expect client to send email=user.email for clarity, but we don't use it for lookup.
    # To verify, client must send current password in new_password? Not ideal; define separate schema if needed.
    # Here we assume payload has fields: email, new_password; we can't verify old password with current schema.
    # Therefore, deny if schema doesn't provide old password. Recommend using admin endpoint or reset flow.
    raise HTTPException(status_code=400, detail='Self password change requires current password; use reset flow or admin change')


@router.get('/admin/roles', response_model=list[schemas.RoleOut])
def list_roles(db: Session = Depends(get_db), token_data: dict = Depends(auth.get_current_user)):
    if 'admin' not in token_data.get('roles', []):
        raise HTTPException(status_code=403, detail='admin role required')
    roles = db.query(models.Role).all()
    return roles


@router.post('/admin/add-role')
def add_role(payload: schemas.RolePayload, db: Session = Depends(get_db), token_data: dict = Depends(auth.get_current_user)):
    if 'admin' not in token_data.get('roles', []):
        raise HTTPException(status_code=403, detail='admin role required')
    role = db.query(models.Role).filter(models.Role.name==payload.role).first()
    if role:
        raise HTTPException(status_code=400, detail='Role exists')
    role = models.Role(name=payload.role, description=payload.description)
    db.add(role)
    db.commit()
    try:
        db.execute(text("INSERT INTO audit_logs(actor_user_id, action, metadata) VALUES(:id,:a, to_jsonb(:m::text))"),
                   {"id": int(token_data.get('sub')), "a": "admin_add_role", "m": payload.role})
        db.commit()
    except Exception:
        db.rollback()
    return {"status":"ok"}


@router.post('/admin/update-role')
def update_role(payload: schemas.RoleUpdate, db: Session = Depends(get_db), token_data: dict = Depends(auth.get_current_user)):
    if 'admin' not in token_data.get('roles', []):
        raise HTTPException(status_code=403, detail='admin role required')
    role = db.query(models.Role).filter(models.Role.name==payload.role).first()
    if not role:
        raise HTTPException(status_code=404, detail='Role not found')
    # prevent renaming admin away or to duplicate name
    if payload.new_name:
        if role.name == 'admin':
            raise HTTPException(status_code=400, detail='Cannot rename default admin role')
        exists = db.query(models.Role).filter(models.Role.name==payload.new_name).first()
        if exists:
            raise HTTPException(status_code=400, detail='Role name already exists')
        role.name = payload.new_name
    if payload.description is not None:
        role.description = payload.description
    db.add(role)
    db.commit()
    try:
        db.execute(text("INSERT INTO audit_logs(actor_user_id, action, metadata) VALUES(:id,:a, to_jsonb(:m::text))"),
                   {"id": int(token_data.get('sub')), "a": "admin_update_role", "m": payload.role})
        db.commit()
    except Exception:
        db.rollback()
    return {"status":"ok"}


@router.post('/admin/remove-role')
def remove_role(payload: schemas.RolePayload, db: Session = Depends(get_db), token_data: dict = Depends(auth.get_current_user)):
    if 'admin' not in token_data.get('roles', []):
        raise HTTPException(status_code=403, detail='admin role required')
    if payload.role == 'admin':
        raise HTTPException(status_code=400, detail='Cannot remove default admin role')
    role = db.query(models.Role).filter(models.Role.name==payload.role).first()
    if not role:
        raise HTTPException(status_code=404, detail='Role not found')
    db.delete(role)
    db.commit()
    try:
        db.execute(text("INSERT INTO audit_logs(actor_user_id, action, metadata) VALUES(:id,:a, to_jsonb(:m::text))"),
                   {"id": int(token_data.get('sub')), "a": "admin_remove_role", "m": payload.role})
        db.commit()
    except Exception:
        db.rollback()
    return {"status":"ok"}


@router.post('/admin/remove-user')
def admin_remove_user(payload: schemas.RemoveUser, db: Session = Depends(get_db), token_data: dict = Depends(auth.get_current_user)):
    if 'admin' not in token_data.get('roles', []):
        raise HTTPException(status_code=403, detail='admin role required')
    user = db.query(models.User).filter(models.User.email==payload.email).first()
    if not user:
        raise HTTPException(status_code=404, detail='User not found')
    # Prevent deleting the last active admin user
    user_roles = [r.name for r in user.roles]
    if 'admin' in user_roles and user.is_active:
        if _count_active_admins(db) <= 1:
            raise HTTPException(status_code=400, detail='Cannot delete the last active admin')
    db.delete(user)
    db.commit()
    try:
        db.execute(text("INSERT INTO audit_logs(actor_user_id, action, target_email) VALUES(:id,:a,:t)"),
                   {"id": int(token_data.get('sub')), "a": "admin_remove_user", "t": payload.email})
        db.commit()
    except Exception:
        db.rollback()
    return {"status":"ok"}
