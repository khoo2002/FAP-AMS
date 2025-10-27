import os
from jose import jwt, JWTError
from datetime import datetime, timedelta
from passlib.context import CryptContext
import uuid
import hashlib
import base64
from fastapi import HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer

# attempt to import cryptography for runtime key generation fallback
try:
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    _HAS_CRYPTO = True
except Exception:
    _HAS_CRYPTO = False

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

PRIVATE_KEY_PATH = os.environ.get('PRIVATE_KEY_PATH', '/keys/private_key.pem')
PUBLIC_KEY_PATH = os.environ.get('PUBLIC_KEY_PATH', '/keys/public_key.pem')

_PRIVATE_KEY = None
_PUBLIC_KEY = None

# cached kid value
_KID = None

ALGORITHM = "RS256"

def _get_env_int(name: str, default: int) -> int:
    val = os.environ.get(name)
    if val is None:
        return default
    val = str(val).strip()
    if val == "":
        return default
    try:
        return int(val)
    except Exception:
        return default

def _get_env_bool(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    sval = str(val).strip()
    if sval == "":
        return default
    return sval.lower() in ("1","true","yes","on")

ACCESS_TOKEN_EXPIRE_MINUTES = _get_env_int('ACCESS_TOKEN_EXPIRE_MINUTES', 60)
# Issuer (default to PUBLIC_BASE_URL if set, else a static string)
ISSUER = (os.environ.get('JWT_ISSUER') or os.environ.get('PUBLIC_BASE_URL', '').rstrip('/') or 'simple-auth-service')
# Optional audience support (comma-separated for multiple)
_AUDIENCE_RAW = (os.environ.get('JWT_AUDIENCE') or '').strip()
JWT_AUDIENCE: list[str] | None = None
if _AUDIENCE_RAW:
    JWT_AUDIENCE = [a.strip() for a in _AUDIENCE_RAW.split(',') if a.strip()]
    if len(JWT_AUDIENCE) == 0:
        JWT_AUDIENCE = None

# Password policy
MIN_PASSWORD_LENGTH = _get_env_int('MIN_PASSWORD_LENGTH', 8)
REQUIRE_DIGIT = _get_env_bool('REQUIRE_DIGIT', True)
REQUIRE_LETTER = _get_env_bool('REQUIRE_LETTER', True)
REQUIRE_SPECIAL = _get_env_bool('REQUIRE_SPECIAL', False)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

def _load_private_key():
    global _PRIVATE_KEY
    if _PRIVATE_KEY is None:
        try:
            with open(PRIVATE_KEY_PATH, 'rb') as f:
                _PRIVATE_KEY = f.read()
        except Exception as e:
            # try to recover by generating in-memory keys
            try:
                _ensure_keys_loaded()
            except Exception:
                raise RuntimeError(f"Cannot read private key: {e}")
    return _PRIVATE_KEY

def _load_public_key():
    global _PUBLIC_KEY
    if _PUBLIC_KEY is None:
        try:
            with open(PUBLIC_KEY_PATH, 'rb') as f:
                _PUBLIC_KEY = f.read()
        except Exception as e:
            # try to recover by generating in-memory keys
            try:
                _ensure_keys_loaded()
            except Exception:
                raise RuntimeError(f"Cannot read public key: {e}")
    return _PUBLIC_KEY


def _generate_rsa_keypair():
    """Generate an in-memory RSA keypair and return (private_pem_bytes, public_pem_bytes)."""
    if not _HAS_CRYPTO:
        raise RuntimeError("cryptography library is not available for key generation")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem


def _ensure_keys_loaded():
    # attempt to load files; if they exist but are invalid PEM, generate fallback keys in-memory
    global _PRIVATE_KEY, _PUBLIC_KEY
    global _KID
    # First attempt: read files if present
    try:
        _load_private_key()
        _load_public_key()
        _KID = _compute_kid(_PUBLIC_KEY)
        return
    except Exception:
        # proceed to generate fallback keys
        pass

    try:
        priv, pub = _generate_rsa_keypair()
        _PRIVATE_KEY = priv
        _PUBLIC_KEY = pub
        _KID = _compute_kid(_PUBLIC_KEY)
        # attempt to persist keys to disk for future runs; ignore failures (read-only mount, permissions)
        try:
            # ensure parent dir exists
            os.makedirs(os.path.dirname(PRIVATE_KEY_PATH), exist_ok=True)
            with open(PRIVATE_KEY_PATH, 'wb') as f:
                f.write(_PRIVATE_KEY)
        except Exception:
            # ignore write failures intentionally
            pass
        try:
            with open(PUBLIC_KEY_PATH, 'wb') as f:
                f.write(_PUBLIC_KEY)
        except Exception:
            pass
    except Exception as e:
        raise RuntimeError(f"Failed to load or generate keys: {e}")

def _compute_kid(pub_bytes: bytes):
    # kid is base64url(sha256(pem_bytes)) without padding
    h = hashlib.sha256(pub_bytes).digest()
    return base64.urlsafe_b64encode(h).rstrip(b'=').decode('utf-8')


def get_public_key_pem() -> bytes:
    """Return the public key PEM bytes, generating in-memory fallback if needed."""
    _ensure_keys_loaded()
    return _load_public_key()


def get_private_key_pem() -> bytes:
    """Return the private key PEM bytes, generating fallback if needed."""
    _ensure_keys_loaded()
    return _load_private_key()


def get_kid() -> str:
    global _KID
    if _KID is None:
        _ensure_keys_loaded()
    return _KID


def get_jwks() -> dict:
    """Return JWKS with RSA public key parameters (n/e) and kid."""
    pub = get_public_key_pem()
    kid = get_kid()
    n_b64 = e_b64 = ""
    if _HAS_CRYPTO:
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
            public_key = serialization.load_pem_public_key(pub)
            if isinstance(public_key, _rsa.RSAPublicKey):
                numbers = public_key.public_numbers()
                n_int = numbers.n
                e_int = numbers.e
                import base64
                n_b = n_int.to_bytes((n_int.bit_length() + 7) // 8, byteorder='big')
                e_b = e_int.to_bytes((e_int.bit_length() + 7) // 8, byteorder='big')
                n_b64 = base64.urlsafe_b64encode(n_b).rstrip(b'=').decode('utf-8')
                e_b64 = base64.urlsafe_b64encode(e_b).rstrip(b'=').decode('utf-8')
        except Exception:
            pass
    jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": ALGORITHM,
        "kid": kid,
    }
    if n_b64 and e_b64:
        jwk["n"] = n_b64
        jwk["e"] = e_b64
    return {"keys": [jwk]}

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def get_password_hash(password):
    return pwd_context.hash(password)

def password_is_strong(password: str) -> tuple[bool, str]:
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters long"
    if REQUIRE_DIGIT and not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit"
    if REQUIRE_LETTER and not any(c.isalpha() for c in password):
        return False, "Password must contain at least one letter"
    if REQUIRE_SPECIAL and not any(not c.isalnum() for c in password):
        return False, "Password must contain at least one special character"
    return True, ""

def create_access_token(subject: str, roles: list[str]):
    _ensure_keys_loaded()
    private_key = _load_private_key()
    kid = get_kid()
    now = datetime.utcnow()
    expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    jti = str(uuid.uuid4())
    payload = {
        "sub": subject,
        "roles": roles,
        "exp": int(expire.timestamp()),
        "iat": int(now.timestamp()),
        "jti": jti,
        "iss": ISSUER
    }
    if JWT_AUDIENCE:
        payload["aud"] = JWT_AUDIENCE if len(JWT_AUDIENCE) > 1 else JWT_AUDIENCE[0]
    token = jwt.encode(payload, private_key, algorithm=ALGORITHM, headers={"kid": kid})
    return token

def decode_token(token: str):
    _ensure_keys_loaded()
    public_key = _load_public_key()
    try:
        if JWT_AUDIENCE:
            data = jwt.decode(token, public_key, algorithms=[ALGORITHM], issuer=ISSUER, audience=JWT_AUDIENCE)
        else:
            data = jwt.decode(token, public_key, algorithms=[ALGORITHM], issuer=ISSUER)
        return data
    except JWTError:
        return None

def get_current_user(token: str = Depends(oauth2_scheme)):
    data = decode_token(token)
    if not data:
        raise HTTPException(status_code=401, detail="Invalid token")
    return data
