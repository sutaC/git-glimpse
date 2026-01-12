from pathlib import Path

def is_text(path: Path) -> bool:
    if path.is_file():
        try:
            with path.open("r", encoding="utf-8", errors="strict") as f:
                f.read(1024)  
        except UnicodeDecodeError:
            return False
    return True