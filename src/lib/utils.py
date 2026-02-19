from src.lib.database_rows import BuildActivity, RepoActivity, UserActivity, Views
from datetime import datetime, timezone
from urllib.parse import quote 
from markdown import markdown
from hashlib import sha256
from pathlib import Path
import requests
import bleach
import re

ALLOWED_TAGS = [
    "p", "pre", "code", "blockquote", "span",
    "ul", "ol", "li",
    "strong", "em",
    "h1", "h2", "h3", "h4", "h5", "h6",
    "table", "thead", "tbody", "tr", "th", "td",
    "a", "hr", "br"
]
ALLOWED_ATTRS = {
    "a": ["href", "title", "rel"],
    "code": ["class"],
    "span": ["class"],
}
GITHUB_URL_REGEX = re.compile(r'^(?:https:\/\/github\.com\/|git@github\.com:)[\w\-]+\/[\w\-]+(?:\.git)?$')
EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# --- repo sections ---
class Section:
    def __init__(self, path: Path) -> None:
        self.name = path.name
        self.path = path
        self.type: str
        self.icon: str
        self.is_root: bool
        # Makes url
        parts = path.parts
        ext = parts.index("extracted")
        rid = parts[ext-1]
        rel_path = '/'.join(quote(p) for p in parts[ext+1:-1])
        self.url = f"/{rid}/{rel_path}/{self.name}"
        self.parent_url = f"/{rid}/{rel_path}"

class FileSection(Section):
    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self.type = "file"
        self.icon = "file_icon.svg"
        self.is_markdown = self.path.suffix.lower() == ".md"
        self._is_text: bool | None = None
        self._content: str | None = None
        self.is_root = False

    def is_text(self) -> bool:
        if self._is_text is not None:
            return self._is_text
        self._is_text = True
        try:
            with self.path.open("r", encoding="utf-8", errors="strict") as f:
                f.read(1024)  
        except UnicodeDecodeError:
            self._is_text = False
        return self._is_text

    def load_content(self) -> str:
        if not self.is_text(): raise ValueError("Cannot load contents of non-text file")
        if self._content: return self._content
        content = self.path.read_text(errors="skip")
        if self.is_markdown: 
            content = render_markdown(content)
        self._content = content
        return self._content

class DirSection(Section):
    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self.type = "dir"
        self.icon = "folder_icon.svg"
        self.is_root = path.name == "extracted"
        self.children: list[Section] = sorted(
            (build_section(ch) for ch in path.iterdir()),
            key=lambda s: (s.type == "file", s.name.lower())
        )

    def find_readme_child(self) -> FileSection | None:
        for ch in self.children:
            if isinstance(ch, FileSection) and ch.name.lower() == "readme.md":
                return ch
        return None
    
def build_section(path: Path) -> Section:
    if path.is_file(): return FileSection(path)
    else: return DirSection(path)
    
def build_parentchain(path: Path, repo_root: Path) -> list[str]:
    rel_parts = path.relative_to(repo_root / "extracted").parts[:-1]  # exclude file itself
    return ['/'.join(rel_parts[:i+1]) for i in range(len(rel_parts))]

# --- validatiors ---
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

def is_vaild_status(status: str) -> bool:
    return status in ['p', 's', 'v', 'f', 'r']

# --- parsers ---
def timestamp_to_str(timestamp: int) -> str:
    if not timestamp: return "?"
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

def size_to_str(size: int | None) -> str:
    if not isinstance(size, int): return '?'
    for unit in ("B", "KB", "MB"):
        if size < 1024:
            return f"{size} {unit}"
        size //= 1024
    return f"{size} GB"

def code_to_status(code: str):
    match code:
        case 'p': return "pending"
        case 's': return "success"
        case 'f': return "failed"
        case 'v': return "violation"
        case 'r': return "running"
        case _: return "?"

def code_to_role(code: str) -> str:
    match code:
        case 'a': return "admin"
        case 'u': return "user"
        case _: return "?"

def builds_activity_to_readable(builds: list[BuildActivity]):
    return [
        (b.id, b.repo_id, b.user_id, b.user_login, code_to_status(b.status), b.code, timestamp_to_str(b.timestamp), size_to_str(b.size))
        for b in builds
    ]

def users_activity_to_readable(users: list[UserActivity]):
    return [
        (u.id, u.login, u.email, u.is_verified, u.is_banned, code_to_role(u.role), 
         timestamp_to_str(u.created), u.inactive)
        for u in users
    ]

def repos_activity_to_readable(repos: list[RepoActivity]):
    return [
        (r.id, r.user_id, r.user_login, r.url, r.has_key, 
         timestamp_to_str(r.created), code_to_status(r.status), size_to_str(r.size), 
         timestamp_to_str(r.timestamp), r.hidden)
        for r in repos
    ]

def views_to_readable(views: list[Views]):
    return [
        (v.client, v.location, v.repo, timestamp_to_str(v.timestamp))
        for v in views
    ]

def detect_client(ua: str) -> str:
    ua = ua.lower()
    if "bot" in ua or "spider" in ua or "crawl" in ua:
        return "bot"
    if "firefox" in ua:
        return "firefox_mobile" if "mobile" in ua else "firefox"
    if "edg" in ua:
        return "edge"
    if "opr" in ua or "opera" in ua:
        return "opera"
    if "chrome" in ua:
        return "chrome_mobile" if "mobile" in ua else "chrome"
    if "safari" in ua:
        return "safari"
    return "unknown"

def detect_location(ip: str) -> str | None:
    if ip == "127.0.0.1": return None
    try:
        r  = requests.get(f"https://ipapi.co/{ip}/country", timeout=1)
        if r.status_code == 200:
            code = r.text.strip()
            return code if len(code) == 2 else None
    except Exception:
        pass
    return None

def viewer_hash(day: int, user_id: int | None = None, ip: str | None = None, ua: str | None = None) -> str:
    assert user_id or (ip and ua)
    if user_id: return sha256(f"u:{user_id}:{day}".encode()).hexdigest()
    return sha256(f"a:{ip}:{ua}:{day}".encode()).hexdigest()

def render_markdown(text: str) -> str:
    text = markdown(
        text, 
        extensions=["fenced_code", "tables", "codehilite"],
        output_format="html"
    )
    text = bleach.clean(
        text,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRS,
        protocols=["http", "https", "mailto"],
        strip=True
    )
    text = bleach.linkify(
        text, 
        callbacks=[bleach.callbacks.nofollow, bleach.callbacks.target_blank]
    )
    return text