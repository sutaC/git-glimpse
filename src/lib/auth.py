"""Module provides authentication functions and authorization decotators for Flask endpoints."""
from urllib.parse import urlparse
from typing import NamedTuple
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
