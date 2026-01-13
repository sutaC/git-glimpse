from functools import wraps
import hashlib
import secrets
from flask import abort, g, redirect, request

class User():
    def __init__(
        self,
        session_id: str,
        user_id: int,
        login: str,
        role: str,
        is_verified: bool
    ) -> None:
        self.session_id: str = session_id
        self.user_id: int = user_id
        self.login: str = login
        self.role: str = role
        self.is_verified: bool = is_verified

def hash_password(password: str, salt: str) ->  str:
    s = (password+salt).encode()
    hash = hashlib.sha256(s)
    return hash.digest().hex()

def generate_salt() -> str:
    return secrets.token_hex(32)

def login_required():
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if g.user is None:
                if request.accept_mimetypes.accept_html:
                    return redirect("/login")
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
