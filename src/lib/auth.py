"""Module provides authentication functions and authorization decotators for Flask endpoints."""
from urllib.parse import urlparse, quote, quote_from_bytes
from flask import abort, redirect, g, request
from typing import NamedTuple
from functools import wraps
import bcrypt
import time
import os

_ENV = os.environ.get("ENV", "dev")

class SessionUser(NamedTuple):
    session_id: str
    user_id: int
    login: str
    role: str
    is_verified: bool
    inactive: bool
    is_banned: bool

_WHITELIST_NEXT_URL_PREF = [
    "/dashboard",
    "/reset",
    "/repos",
    "/verify",
    "/admin",
    "/user"
]

def safe_redirect_url(next_url: str | None) -> str:
    """Gives safe redirect URL provided unknown redirect URL.
    
    If `next_url` is not provided or it is marked as unsafe then function will return defaulr redirect URL `/dashboard`.

    Args:
        next_url: Unknown redirect URL.

    Returns:
        Safe redirect URL.
    """
    if not next_url:
        return "/dashboard"
    parsed = urlparse(next_url)
    if parsed.scheme or parsed.netloc:
        return "/dashboard"
    if not any(parsed.path.startswith(w) for w in _WHITELIST_NEXT_URL_PREF):
        return "/dashboard"
    return next_url

def hash_password(password: str) ->  str:
    """Hashes password cryptographic secure.

    Args:
        password: Password to hash.

    Returns:
        Hashed password.
    """
    enc = password.encode()
    hashed = bcrypt.hashpw(enc, bcrypt.gensalt()) 
    return hashed.decode()

def check_password(password: str, hashed_password: str) -> bool:
    """Checks if given passwords match.

    Args:
        password: Text password.
        hashed_password: Hashed password.

    Returns:
        True if passwords match.
    """
    try: return bcrypt.checkpw(password.encode(), hashed_password.encode())
    except: return False

def get_session_expiriation(role: str) -> int:
    """Gives session expiriation timestamp based on role.

    In `dev` enviroment function lifespan will be 24h.
    In `dev` enviroment function lifespan will be:
    - 1h for regular users.
    - 20min for admins.

    Args:
        role: User role code.

    Returns:
        Session expiriation timestamp.
    """
    if _ENV != "prod": return int(time.time()) + 86_400 # now + 24h (development)
    return int(time.time()) + (1200 if role == 'a' else 3600) # now + 1h (user) + 20min (admin) 

# --- decotators ---
def login_required():
    """Allows only logged-in users."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if g.user is None:
                if request.accept_mimetypes.accept_html:
                    return redirect(f"/login?next={quote(request.path.rstrip("/"))}{quote_from_bytes("?".encode()+request.query_string) if request.query_string else ""}")
                abort(401)
            return f(*args, **kwargs)
        return wrapper
    return decorator

def verification_required():
    """Allows only verified users."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if g.user is None or not g.user.is_verified:
                if request.accept_mimetypes.accept_html:
                    return redirect("/verify")
                abort(401)
            return f(*args, **kwargs)
        return wrapper
    return decorator

def role_required(role: str):
    """Allows only users with given role.
    
    Args:
        role: Allowed role code.
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if g.user is None:
                abort(401)
            if g.user.role != role:
                abort(403)
            return f(*args, **kwargs)
        return wrapper
    return decorator

def not_banned_required():
    """Allows only not banned users."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if g.user is None:
                abort(401)
            if g.user.is_banned:
                return redirect("/banned")
            return f(*args, **kwargs)
        return wrapper
    return decorator
