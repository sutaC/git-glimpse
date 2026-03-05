from rcssmin import cssmin
from rjsmin import jsmin
from pathlib import Path
import hashlib
import shutil
import json
import gzip

if __name__ == "__main__":
    PROJECT_ROOT = Path(__file__).parent.parent
    SRC = PROJECT_ROOT / "src" / "static"
    DIST = SRC / "dist"

    shutil.rmtree(DIST)
    DIST.mkdir(exist_ok=True)

    manifest = {}

    for path in SRC.rglob("*"):
        if not path.is_file():
            continue
        if "dist" in path.parts:
            continue
        rel = path.relative_to(SRC)
        content: bytes = path.read_bytes()
        # Minify
        if path.suffix == ".js":
            content = str(jsmin(content.decode(errors="replace"))).encode(errors="replace")
        elif path.suffix == ".css":
            content = str(cssmin(content.decode(errors="replace"))).encode(errors="replace")
        # Hash
        hash = hashlib.sha256(content).hexdigest()[:8]
        new_name = f"{path.stem}.{hash}{path.suffix}"
        # Write
        dest = DIST / new_name
        dest.write_bytes(content)
        manifest[str(rel)] = new_name
        # Gzip
        if path.suffix in [".css", ".js", ".svg", ".txt"]: # Only text files
            with gzip.open(str(dest) + ".gz", "wb") as f:
                f.write(content)
        # Log
        print(f"Added: {rel}")
    
    with open(DIST / "manifest.json", "w") as f:
        json.dump(manifest, f)

    print("Static build complete")