from flask import abort, redirect, g, request
from functools import wraps
import bcrypt
import time
import os

ENV = os.environ.get("ENV", "dev")

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

def hash_password(password: str) ->  str:
    enc = password.encode()
    hashed = bcrypt.hashpw(enc, bcrypt.gensalt()) 
    return hashed.decode()

def check_password(password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed_password.encode())

def get_session_expiriation(role: str) -> int:
    if ENV != "prod": return int(time.time()) + 86_400 # now + 24h (development)
    return int(time.time()) + (1200 if role == 'a' else 3600) # now + 1h (user) + 20min (admin) 

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
