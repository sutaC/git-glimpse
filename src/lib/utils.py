from datetime import datetime, timezone
from pathlib import Path
import re

GITHUB_URL_REGEX = re.compile(r'^(?:https:\/\/github\.com\/|git@github\.com:)[\w\-]+\/[\w\-]+(?:\.git)?$')
EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def is_valid_repo_url(url: str) -> bool:
    return bool(GITHUB_URL_REGEX.match(url))

def is_valid_email(email: str) -> bool:
    return bool(EMAIL_REGEX.match(email))

def is_valid_password(password: str) -> str | None:
    if len(password) < 12:
        return "Password must be min 12 characters long"
    if len(password) >= 128:
        return "Password must max 128 characters long"
    if password != password.strip():
        return "Password cannot have leading/trailling spaces"    

def is_text(path: Path) -> bool:
    if path.is_file():
        try:
            with path.open("r", encoding="utf-8", errors="strict") as f:
                f.read(1024)  
        except UnicodeDecodeError:
            return False
    return True

def timestamp_to_str(timestamp: int) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

def size_to_str(size: int) -> str:
    for unit in ("B", "KB", "MB"):
        if size < 1024:
            return f"{size} {unit}"
        size //= 1024
    return f"{size} GB"
