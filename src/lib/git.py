from pathlib import Path
import time
from cryptography.fernet import Fernet 
import subprocess
import tempfile
import shutil
import os

FERNET = Fernet(os.environ["FERNET_KEY"]) # REQUIRED

MAX_REPO_SIZE = 100 * 1024 * 1024  # 100 MB
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
MAX_FILE_COUNT = 10_000
MAX_DIR_COUNT = 5_000
MAX_DEPTH = 20
MAX_SCAN_TIME = 10 # 10 s
MAX_CLONE_TIME = 30 # 30 s

def check_repo_limits(path: Path):
    total_size = 0
    file_count = 0
    dir_count = 0
    time_limit = time.monotonic()
    for f in path.rglob("*"):
        if f.is_file():
            if time.monotonic() - time_limit > MAX_SCAN_TIME:
                raise RuntimeError("Exceeded time limit for repo scan")
            file_count += 1
            if file_count > MAX_FILE_COUNT:
                raise RuntimeError("Too many files")
            size = f.stat().st_size
            if size > MAX_FILE_SIZE:
                raise RuntimeError(f"File too large: {f}")
            total_size += size
            if total_size > MAX_REPO_SIZE:
                raise RuntimeError("Repo too large")
        if f.is_dir():
            dir_count += 1
            if dir_count > MAX_DIR_COUNT:
                raise RuntimeError("Too many directories")
            depth = len(f.relative_to(path).parts)
            if depth > MAX_DEPTH:
                raise RuntimeError("Exceeded depth limit")
        elif f.is_symlink():
            raise RuntimeError("Symlinks are not allowed")
        elif f.is_fifo():
            raise RuntimeError("Fifo are not allowed")
        elif f.is_char_device():
            raise RuntimeError("Char devices are not allowed")
        elif f.is_socket():
            raise RuntimeError("Sockets are not allowed")
        elif f.is_block_device():
            raise RuntimeError("Block devices are not allowed")
   
def clone_repo(url: str, target_dir: Path, ssh_key: str | None = None):
    env = None
    key_path = None
    try:
        if ssh_key:
            key_path = write_ssh_key_temp(ssh_key)
            env = {
                **os.environ,
                "GIT_SSH_COMMAND": f"ssh -i {key_path} -o StrictHostKeyChecking=no"
            }
        with tempfile.TemporaryDirectory() as tmpdir_str:
            tmpdir = Path(tmpdir_str)
            try:
                subprocess.run([
                        "git", "clone", 
                        "--depth", "1",
                        "--single-branch",
                        "--no-tags",
                        "--no-recurse-submodules",
                        url, str(tmpdir)
                    ],
                    check=True,
                    env=env,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    timeout=MAX_CLONE_TIME
                )
            except subprocess.CalledProcessError as e:
                raise RuntimeError(f"Git clone failed: {e.stderr.decode()}") from e
            # Removes git
            git_dir = tmpdir / ".git"
            if git_dir.is_dir(): shutil.rmtree(git_dir, ignore_errors=True)
            # Checks git modules
            gitmodules_dir = tmpdir / ".gitmodules"
            if gitmodules_dir.exists(): 
                raise RuntimeError("Git modules are not allowed")
            # Checks repo limits
            check_repo_limits(tmpdir)
            # Ensures target dir is empty
            if target_dir.exists():
                shutil.rmtree(target_dir)
            target_dir.mkdir(exist_ok=True, parents=True)
            # Moves files to target_dir
            for item in tmpdir.iterdir():
                shutil.move(item, target_dir)
            # Restricts permissions
            for path in target_dir.rglob("*"):
                if path.is_file():
                    path.chmod(0o400)
                elif path.is_dir():
                    path.chmod(0o500)
    finally:
        if key_path: key_path.unlink(missing_ok=True)

def encrypt_ssh_key(ssh_key: str) -> str:
    return FERNET.encrypt(ssh_key.encode()).decode()

def decrypt_ssh_key(ssh_key: str) -> str:
    return FERNET.decrypt(ssh_key.encode()).decode()

def write_ssh_key_temp(ssh_key: str) -> Path:
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write(ssh_key)
        key_path = Path(f.name)
        key_path.chmod(0o600)
    return key_path