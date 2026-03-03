"""This module provides basic utility functions for purposes like:
- User input validation
- Parsing data for templates
"""
from src.lib.database_rows import BuildActivity, RepoActivity, UserActivity, Views
from datetime import datetime, timezone
import re

_GITHUB_URL_REGEX = re.compile(r'^(?:https:\/\/github\.com\/|git@github\.com:)[\w\-]+\/[\w\-]+(?:\.git)?$')
_EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# --- validatiors ---
def is_valid_repo_url(url: str) -> bool:
    """Validate repository URL.
    
    Valid URL will follow this pattern: 
    - `https://github.com/user/repo.git`
    - `git@github.com:user/repo.git`.

    Args:
        url: URL to validate.
    
    Returns:
        True if URL is valid.

    Notes:
        This function checks only format. It does not verify
        URL resource existence. 
    """
    return bool(_GITHUB_URL_REGEX.match(url))

def is_valid_email(email: str) -> bool:
    """Validate email.
    
    Args:
        email: Email to validate.
    
    Returns:
        True if email is valid.

    Notes:
        This function checks only format. It does not verify
        domain existence or mailbox availability. 
    """
    return bool(_EMAIL_REGEX.match(email))

def is_valid_password(password: str) -> str | None:
    """Validate password.

    Password is valid when meets the following conditions:
    - Minimum 12 characters long
    - Maximum 128 characters long
    - Does not have leading or trailling spaces

    Args:
        password: Password to validate.

    Returns:
        Error message if password is invalid, otherwise None. 
    """
    if len(password) < 12:
        return "Password must be min 12 characters long"
    if len(password) >= 128:
        return "Password must max 128 characters long"
    if password != password.strip():
        return "Password cannot have leading/trailling spaces"    
    return None

def is_vaild_status(status: str) -> bool:
    """Validate status.

    Args:
        status: Status to validate.

    Returns:
        True if status if valid.
    """
    return status in ['p', 's', 'v', 'f', 'r']

# --- parsers ---
def timestamp_to_str(timestamp: int) -> str:
    """Parses timestamp to string format.

    Args:
        timestamp: Timestamp to parse.

    Returns:
        Timestamp in string format.
    """
    if not timestamp: return "?"
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

def size_to_str(size: int | None) -> str:
    """Parses size to string format.

    Returns number with greatest unit suffix (B, KB, MB, GB), rounding down.
    Returns "?" if size is None. 

    Args:
        size: Size to parse.

    Returns:
        Size in string format.
    """
    if not isinstance(size, int): return '?'
    for unit in ("B", "KB", "MB"):
        if size < 1024:
            return f"{size} {unit}"
        size //= 1024
    return f"{size} GB"

def code_to_status(code: str):
    """Parses status code to string format.

    Args:
        code: Status code to parse.

    Returns:
        Status in string format.
    """
    match code:
        case 'p': return "pending"
        case 's': return "success"
        case 'f': return "failed"
        case 'v': return "violation"
        case 'r': return "running"
        case _: return "?"

def code_to_role(code: str) -> str:
    """Parses role code to string format.

    Args:
        code: Role code to parse.

    Returns:
        Role in string format.
    """
    match code:
        case 'a': return "admin"
        case 'u': return "user"
        case _: return "?"

def builds_activity_to_readable(builds: list[BuildActivity]):
    """Parses BuildActivity list to string formatted tuple for template display.

    Args:
        builds: BuildActivity list to parse.
    
    Returns:
        String formatted tuple.
    """
    return [
        (b.id, b.repo_id, b.user_id, b.user_login, code_to_status(b.status), b.code, timestamp_to_str(b.timestamp), size_to_str(b.size))
        for b in builds
    ]

def users_activity_to_readable(users: list[UserActivity]):
    """Parses UserActivity list to string formatted tuple for template display.

    Args:
        builds: UserActivity list to parse.
    
    Returns:
        String formatted tuple.
    """
    return [
        (u.id, u.login, u.email, u.is_verified, u.is_banned, code_to_role(u.role), 
         timestamp_to_str(u.created), u.inactive)
        for u in users
    ]

def repos_activity_to_readable(repos: list[RepoActivity]):
    """Parses RepoActivity list to string formatted tuple for template display.

    Args:
        builds: RepoActivity list to parse.
    
    Returns:
        String formatted tuple.
    """
    return [
        (r.id, r.user_id, r.user_login, r.url, r.has_key, 
         timestamp_to_str(r.created), code_to_status(r.status), size_to_str(r.size), 
         timestamp_to_str(r.timestamp), r.hidden)
        for r in repos
    ]

def views_to_readable(views: list[Views]):
    """Parses Views list to string formatted tuple for template display.

    Args:
        builds: Views list to parse.
    
    Returns:
        String formatted tuple.
    """
    return [
        (v.client, v.location, v.repo, timestamp_to_str(v.timestamp))
        for v in views
    ]
