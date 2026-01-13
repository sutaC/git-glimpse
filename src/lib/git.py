from tempfile import NamedTemporaryFile
from pathlib import Path
import subprocess
import os

def clone_repo(url: str, target_dir: Path, ssh_key: str | None = None):
    target_dir.mkdir()
    env = None
    key_path = None
    try:
        if ssh_key:
            with NamedTemporaryFile("w", delete=False) as f:
                f.write(ssh_key)
                key_path = f.name
            if key_path: os.chmod(key_path, 600)
            env = {
                **os.environ,
                "GIT_SSH_COMMAND": f"ssh -i {key_path} -o StrictHostKeyChecking=no"
            }
        subprocess.run(
            ["git", "clone", url, str(target_dir)],
            check=True,
            env=env
        )
    finally:
        if key_path and Path(key_path).exists(): os.remove(key_path)
