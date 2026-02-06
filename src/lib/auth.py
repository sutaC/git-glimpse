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

WHITELIST_NEXT_URL_PREF = [
    "/dashboard",
    "/reset",
    "/repos",
    "/verify",
    "/admin",
    "/user"
]

def safe_redirect_url(next_url: str | None) -> str:
    if not next_url:
        return "/dashboard"
    parsed = urlparse(next_url)
    if parsed.scheme or parsed.netloc:
        return "/dashboard"
    if not any(parsed.path.startswith(w) for w in WHITELIST_NEXT_URL_PREF):
        return "/dashboard"
    return next_url

def hash_password(password: str) ->  str:
    enc = password.encode()
    hashed = bcrypt.hashpw(enc, bcrypt.gensalt()) 
    return hashed.decode()

def check_password(password: str, hashed_password: str) -> bool:
    try: return bcrypt.checkpw(password.encode(), hashed_password.encode())
    except: return False

def get_session_expiriation(role: str) -> int:
    if _ENV != "prod": return int(time.time()) + 86_400 # now + 24h (development)
    return int(time.time()) + (1200 if role == 'a' else 3600) # now + 1h (user) + 20min (admin) 

def login_required():
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
