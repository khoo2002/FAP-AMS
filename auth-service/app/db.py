from sqlalchemy import create_engine, text
import os
from sqlalchemy.orm import sessionmaker, declarative_base

engine = None
SessionLocal = None
Base = declarative_base()
AUDIT_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS audit_logs(
    id SERIAL PRIMARY KEY,
    event_time TIMESTAMPTZ DEFAULT now(),
    actor_user_id INTEGER NULL,
    actor_email TEXT NULL,
    action TEXT NOT NULL,
    target_email TEXT NULL,
    ip TEXT NULL,
    user_agent TEXT NULL,
    metadata JSONB NULL
);
"""

def init_db(database_url: str):
    global engine, SessionLocal
    if not database_url:
        raise RuntimeError("DATABASE_URL is not set")
    # make some attempts to connect to the DB (docker-compose may start app before Postgres is ready)
    import time
    from sqlalchemy import exc

    max_attempts = 8
    delay = 1.0
    last_err = None
    for attempt in range(1, max_attempts + 1):
        try:
            engine = create_engine(database_url, pool_pre_ping=True)
            SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
            # try a lightweight operation to verify connectivity
            conn = engine.connect()
            conn.close()
            break
        except exc.SQLAlchemyError as e:
            last_err = e
            if attempt == max_attempts:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 5.0)

    # create tables if not exist (simple approach)
    from app import models
    Base.metadata.create_all(bind=engine)
    # Ensure new columns from model changes exist (simple runtime migration)
    try:
        with engine.begin() as conn:
            try:
                print('DB migration: checking for roles.description column')
                r = conn.execute(text("SELECT column_name FROM information_schema.columns WHERE table_name='roles' AND column_name='description';"))
                exists = r.first() is not None
                if not exists:
                    print('DB migration: adding roles.description column')
                    conn.execute(text("ALTER TABLE roles ADD COLUMN description TEXT;"))
                else:
                    print('DB migration: roles.description already exists')
            except Exception as inner_e:
                print('DB migration: failed to check/add column:', inner_e)
                raise
            # Add created_at and last_login to users if missing
            cols = {row[0] for row in conn.execute(text("SELECT column_name FROM information_schema.columns WHERE table_name='users';"))}
            if 'created_at' not in cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN created_at TIMESTAMPTZ DEFAULT now();"))
            if 'last_login' not in cols:
                conn.execute(text("ALTER TABLE users ADD COLUMN last_login TIMESTAMPTZ NULL;"))
            # Create password_reset_tokens table if missing
            r = conn.execute(text("SELECT to_regclass('public.password_reset_tokens');"))
            if r.scalar() is None:
                conn.execute(text("""
                    CREATE TABLE password_reset_tokens(
                        id SERIAL PRIMARY KEY,
                        token TEXT UNIQUE NOT NULL,
                        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                        expires_at TIMESTAMPTZ NOT NULL,
                        used BOOLEAN DEFAULT FALSE,
                        created_at TIMESTAMPTZ DEFAULT now()
                    );
                """))
            # Create audit_logs table if missing
            conn.execute(text(AUDIT_TABLE_SQL))
    except Exception:
        # ignore - best effort migration for development but print
        import traceback
        print('DB migration: exception', traceback.format_exc())
    # dev convenience: create initial admin if none exists and env vars provided
    try:
        from app import auth as auth_module
        db = SessionLocal()
        try:
            user_count = db.query(models.User).count()
            if user_count == 0:
                admin_email = os.environ.get('ADMIN_EMAIL')
                admin_pass = os.environ.get('ADMIN_PASSWORD')
                if admin_email and admin_pass:
                    admin = models.User(email=admin_email, password_hash=auth_module.get_password_hash(admin_pass))
                    role = db.query(models.Role).filter(models.Role.name=='admin').first()
                    if not role:
                        role = models.Role(name='admin')
                        db.add(role)
                        db.commit()
                        db.refresh(role)
                    admin.roles.append(role)
                    db.add(admin)
                    db.commit()
        finally:
            db.close()
    except Exception:
        # ignore in production; this is a small dev convenience
        pass

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
