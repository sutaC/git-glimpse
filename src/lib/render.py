"""Module provides utilities for rendering files and repository templates."""
from pygments.lexers import guess_lexer_for_filename
from pygments.lexers.special import TextLexer
from pygments.formatters import HtmlFormatter
from pygments.util import ClassNotFound
from pygments import highlight
from urllib.parse import quote 
from markdown import markdown
from markupsafe import Markup
from pathlib import Path
from html import escape
import mimetypes
import bleach

_FORMATTER = HtmlFormatter(nowrap=True)

_ALLOWED_TAGS = [
    "p", "pre", "code", "blockquote", "span",
    "ul", "ol", "li",
    "strong", "em",
    "h1", "h2", "h3", "h4", "h5", "h6",
    "table", "thead", "tbody", "tr", "th", "td",
    "a", "hr", "br"
]
_ALLOWED_ATTRS = {
    "a": ["href", "title", "rel"],
    "code": ["class"],
    "span": ["class"],
}
_CODE_EXTENSIONS = {
    ".py", ".js", ".ts", ".go", ".rs", ".java", ".c", ".cpp",
    ".h", ".hpp", ".cs", ".sh", ".bash", ".zsh",
    ".html", ".css", ".scss", ".json", ".yml", ".yaml",
    ".toml", ".ini", ".cfg", ".sql"
}
_FILE_TYPE_MAP = {
    # docs
    ".md": "markdown",
    ".txt": "doc",
    ".rst": "doc",
    # images
    ".png": "image",
    ".jpg": "image",
    ".jpeg": "image",
    ".gif": "image",
    ".svg": "image",
    ".webp": "image",
    # archives
    ".zip": "archive",
    ".tar": "archive",
    ".gz": "archive",
    ".bz2": "archive",
    ".xz": "archive",
    # binaries
    ".exe": "binary",
    ".dll": "binary",
    ".so": "binary",
    ".bin": "binary",
    ".wasm": "binary",
}

# --- sections ---
class Section:
    """Repository section template data parent class.
    
    Args:
        path: Path to repository resource.
    """
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
        self.url = f"/{rid}/"
        if rel_path: self.url += f"{rel_path}/"
        self.url += self.name
        if self.path.is_dir(): self.url = self.url + "/"
        self.parent_url = f"/{rid}/"
        if rel_path: self.parent_url += f"{rel_path}/"

class FileSection(Section):
    """Repository file section template data.
    
    Args:
        path: Path to repository resource.
    """

    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self.type = "file"
        self.icon = "file_icon.svg"
        self._is_text: bool | None = None
        self._content: Markup | None = None
        self.is_root = False
        self.file_type = detect_file_type(path)

    def is_text(self) -> bool:
        """Is file a text file.
        
        Returns:
            True if file is a text file.
        """
        if self._is_text is not None:
            return self._is_text
        self._is_text = is_text(self.path)
        return self._is_text

    def load_content(self) -> Markup:
        """Gives file content safe for html.
        
        Returns:
            File content safe for html
        """
        if not self.is_text(): raise ValueError("Cannot load contents of non-text file")
        if self._content: return self._content
        prerendered = get_prerendered(self.path)
        if prerendered:
            self._content = Markup(prerendered.read_text())
        else:
            content = self.path.read_text(errors="skip")
            self._content = Markup(f'<pre class="file_text">{escape(content)}</pre>')
        return self._content

class DirSection(Section):
    """Repository directory section template data.
    
    Args:
        path: Path to repository resource.
    """

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
        """Finds readme file in direct children of directory.

        Returns:
            If exists an `FileSection` of readme child otherwise None. 
        """
        for ch in self.children:
            if isinstance(ch, FileSection) and ch.name.lower() == "readme.md":
                return ch
        return None
    
def build_section(path: Path) -> Section:
    """Builds section template data class of repository resource.
    
    Args:
        path: Path to repository resource.

    Returns:
        Section template data class.
    """
    if path.is_file(): return FileSection(path)
    else: return DirSection(path)

def is_text(path: Path) -> bool:
    """Checks if path is a text file.
    
    Args:
        path: Patch to check.

    Returns:
        True if path is a text file.
    """
    if not path.is_file(): return False
    try:
        with path.open("r", encoding="utf-8", errors="strict") as f:
            f.read(1024)  
    except UnicodeDecodeError:
        return False
    return True

def detect_file_type(path: Path) -> str:
    """Detects file type.
    
    Args:
        path: Path to file.

    Returns:
        File type (`doc`, `code`, `markdown`, `image`, `archive`, `other`).

    Raises:
        ValueError: If provided path is not a file.
    """
    if not path.is_file(): raise ValueError()
    ext = path.suffix.lower()
    if ext in _CODE_EXTENSIONS:
        return "code"
    if ext in _FILE_TYPE_MAP:
        return _FILE_TYPE_MAP[ext]
    mime, _ = mimetypes.guess_type(path)
    if mime:
        if mime.startswith("text/"):
            return "doc"
        if mime.startswith("image/"):
            return "image"
        if mime in ("application/zip", "application/x-tar"):
            return "archive"
    return "other"

# --- functional ---
def build_parentchain(path: Path, repo_root: Path) -> list[str]:
    """Builds list of parent internal paths.

    Args:
        path: Path to repositiry reosurce (in `extraced/`).
        repo_root: Repository path.

    Returns: 
        List of parent internal paths. 
    """
    rel_parts = path.relative_to(repo_root / "extracted").parts[:-1]  # exclude file itself
    return ['/'.join(rel_parts[:i+1]) for i in range(len(rel_parts))]

# --- rendering ---
def render_markdown(text: str) -> Markup:
    """Renders markdown text.

    Args:
        text: Text to render.

    Returns:
        Renderd markdown text, safe to use in html.
    """
    text = markdown(
        text, 
        extensions=["fenced_code", "tables", "codehilite"],
        output_format="html"
    )
    text = bleach.clean(
        text,
        tags=_ALLOWED_TAGS,
        attributes=_ALLOWED_ATTRS,
        protocols=["http", "https", "mailto"],
        strip=True
    )
    text = bleach.linkify(
        text, 
        callbacks=[bleach.callbacks.nofollow, bleach.callbacks.target_blank]
    )
    return Markup(f'<div class="file_markdown">{text}</div>')

def render_code(text: str, file_name: str) -> Markup:
    """Renders code (highlights) text.

    Args:
        text: Text to render.
        file_name: File name (used for type detection).

    Returns:
        Renderd code text, safe to use in html.
    """
    try: lexer = guess_lexer_for_filename(file_name, text)
    except ClassNotFound: lexer = TextLexer()
    highlighted = highlight(text, lexer, _FORMATTER)
    return Markup(f'<pre class="file_code"><code>{highlighted}</code></pre>')

def get_prerendered(path: Path) -> Path | None:
    """Gives path to prerenderd file form repository resource file path.

    Args:
        path: Repository resource file path.

    Returns:
        Prerenderd file path if exists otherwise None.

    Raises:
        ValueError: If given path is not a file or is not in `repo/extracted/`.
    """
    if not path.is_file() or "extracted" not in path.parts: 
        raise ValueError("Cannot access prerendered path for not a file path")
    ext = path.parts.index("extracted")
    repo_path = Path(*path.parts[:ext])
    rel_path = Path(*path.parts[ext+1:])
    prd_path = repo_path / "html" / (str(rel_path) + ".html")
    if not prd_path.is_file():
        return None
    return prd_path
