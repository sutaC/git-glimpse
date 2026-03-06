"""Module provides Flask helper functoins for managing Flask endpoints."""
from urllib.parse import quote, quote_from_bytes
from flask import Response, abort, redirect, g, request
from functools import wraps

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

def use_cache():
    """Adds ETag caching."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            response = f(*args, **kwargs)
            if not isinstance(response, Response): response = Response(response)
            response.headers.add("Cache-Control", "private, max-age=0, must-revalidate")
            response.add_etag(overwrite=True)
            return response.make_conditional(request)
        return wrapper
    return decorator
