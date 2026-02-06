from cryptography.fernet import Fernet 
from typing import Literal
from pathlib import Path
import zstandard as zstd
import lib.logger as lg
import subprocess
import tempfile
import tarfile
import zipfile
import shutil
import time
import json
import os

FERNET = Fernet(os.environ["FERNET_KEY"]) # REQUIRED

PROJECT_ROOT_PATH = Path(__file__).parent.parent.parent 
REPO_PATH =  PROJECT_ROOT_PATH / "repo"
REPO_PATH.mkdir(exist_ok=True)
SIZE_CACHE_FILE = REPO_PATH / ".size.json"

MAX_REPO_SIZE = 100 * 1024 * 1024  # 100 MB
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
MAX_FILE_COUNT = 10_000
MAX_DIR_COUNT = 5_000
MAX_DEPTH = 20
MAX_SCAN_TIME = 10 # 10 s
MAX_CLONE_TIME = 30 # 30 s

class RepoError(RuntimeError):
    def __init__(self, type: Literal['f', 'v'], code: str, *args: object) -> None:
        super().__init__(*args)
        self.type: Literal['f', 'v'] = type
        self.code: str = code

class RepoLock:
    def __init__(self, repo_path: Path):
        self.lock_file = repo_path / ".extract.lock"
        self.acquired = False

    def acquire(self, timeout: int = 10):
        start = time.time()
        while True:
            try:
                fd = self.lock_file.open("x") # fails if file exist
                fd.write(str(time.time()))
                fd.close()
                self.acquired = True
                return
            except FileExistsError:
                if time.time() - start > timeout:
                    raise RuntimeError("Could not acquire repo lock")
                time.sleep(0.1)

    def release(self):
        if self.acquired and self.lock_file.exists():
            self.lock_file.unlink()
            self.acquired = False

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.release()

def check_repo_limits(path: Path) -> int:
    total_size = 0
    file_count = 0
    dir_count = 0
    time_limit = time.monotonic()
    for f in path.rglob("*"):
        if f.is_file():
            if time.monotonic() - time_limit > MAX_SCAN_TIME:
                raise RepoError('v', lg.Code.SCAN_TIMEOUT)
            file_count += 1
            if file_count > MAX_FILE_COUNT:
                raise RepoError('v', lg.Code.LIMIT_MAX_FILES)
            size = f.stat().st_size
            if size > MAX_FILE_SIZE:
                raise RepoError('v', lg.Code.LIMIT_MAX_FILE)
            total_size += size
            if total_size > MAX_REPO_SIZE:
                raise RepoError('v', lg.Code.LIMIT_MAX_SIZE)
        if f.is_dir():
            dir_count += 1
            if dir_count > MAX_DIR_COUNT:
                raise RepoError('v', lg.Code.LIMIT_MAX_DIRS)
            depth = len(f.relative_to(path).parts)
            if depth > MAX_DEPTH:
                raise RepoError('v', lg.Code.LIMIT_MAX_DEPTH)
        elif f.is_symlink():
            raise RepoError('v', lg.Code.FORBIDDEN_FILE_TYPE)
        elif f.is_fifo():
            raise RepoError('v', lg.Code.FORBIDDEN_FILE_TYPE)
        elif f.is_char_device():
            raise RepoError('v', lg.Code.FORBIDDEN_FILE_TYPE)
        elif f.is_socket():
            raise RepoError('v', lg.Code.FORBIDDEN_FILE_TYPE)
        elif f.is_block_device():
            raise RepoError('v', lg.Code.FORBIDDEN_FILE_TYPE)
    return total_size
   
def clone_repo(url: str, repo_dir: Path, ssh_key: str | None = None) -> tuple[int, int]:
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
                raise RepoError('f', lg.Code.BUILD_EXCEPTION, {"reason": e.stderr.decode()})
            # Removes git
            git_dir = tmpdir / ".git"
            if git_dir.is_dir(): shutil.rmtree(git_dir, ignore_errors=True)
            # Checks git modules
            gitmodules_dir = tmpdir / ".gitmodules"
            if gitmodules_dir.exists(): 
                raise RepoError('v', lg.Code.FORBIDDEN_FILE_TYPE)
            # Checks repo limits
            repo_size = check_repo_limits(tmpdir)
            # Ensures target dir is empty
            if repo_dir.exists():
                remove_protected_dir(repo_dir)
            repo_dir.mkdir(exist_ok=True, parents=True)
            # Moves files to repo_dir archive
            archive_path = repo_dir / "build.tar.zst"
            compress_repo(tmpdir, archive_path)
            archive_path.chmod(0o400)
            # returns repo size
            archive_size = archive_path.stat().st_size
            return repo_size, archive_size
    except RepoError:
        raise # pass RepoErorrs
    except Exception as e:
        raise RepoError('f', lg.Code.BUILD_EXCEPTION, {"reason": str(e)})
    finally:
        if key_path: key_path.unlink(missing_ok=True)

def compress_repo(src_dir: Path, archive_path: Path, compression_level: int = 3):
    with open(archive_path, "wb") as f_out:
        cctx = zstd.ZstdCompressor(level=compression_level)
        with cctx.stream_writer(f_out) as compressor:
            with tarfile.open(fileobj=compressor, mode="w") as tar:
                tar.add(src_dir, arcname="")

def extract_repo(repo_path: Path) -> None:
    archive_path = repo_path / "build.tar.zst"
    if not archive_path.exists(): raise RuntimeError("Archive doesnt exist")
    with RepoLock(repo_path):
        ext_path = repo_path / "extracted"
        if ext_path.exists(): raise RuntimeError("Cannot extract on existing dir")
        ext_path.mkdir(parents=True)
        with tempfile.TemporaryDirectory() as tmpdir_str:
            tmpdir = Path(tmpdir_str)
            with open(archive_path, "rb") as f:
                dctx = zstd.ZstdDecompressor()
                with dctx.stream_reader(f) as reader:
                    with tarfile.open(fileobj=reader, mode="r|*") as tar: # stream mode
                        for member in tar:
                            if member.islnk() or member.issym():
                                raise RuntimeError(f"Symlinks/hardlinks are not allowed: {member.name}")
                            if member.isdev() or member.isfifo():
                                raise RuntimeError(f"Unsupported device in archive: {member.name}")
                            tar.extract(member, path=tmpdir, numeric_owner=False)
            # Checks repo limits
            check_repo_limits(tmpdir)
            # Move from temp dir
            for item in tmpdir.iterdir():
                    shutil.move(item, ext_path)
        # Permissons restrictions
        for path in ext_path.rglob("*"):
            if path.is_file():
                path.chmod(0o400)
            elif path.is_dir():
                path.chmod(0o500)

def remove_protected_dir(path: Path):
    if not path.exists(): return
    path.chmod(0o700)
    for child in path.rglob("*"):
        child.chmod(0o700)
    shutil.rmtree(path)

def remove_extracted(repo_path: Path) -> None:
    ext_path = repo_path / "extracted"
    if not ext_path.exists():
        return 
    with RepoLock(repo_path):
        if ext_path.exists():
            remove_protected_dir(ext_path)

def get_repo_path(repo_path: Path, sub_path: Path) -> Path:
    ext_path = repo_path / "extracted"
    if not ext_path.exists():
        extract_repo(repo_path)
        lg.log(lg.Event.REPO_EXTRACTED, repo_id=repo_path.name)
    path = (ext_path / sub_path).resolve()
    if not path.is_relative_to(ext_path): raise RuntimeError("Invalid path")
    if path.is_symlink() or any(p.is_symlink() for p in path.parents): raise RuntimeError("Invalid path")
    if not path.exists(): raise RuntimeError("Invalid path")
    return path

def zip_repo(ext_path: Path, zip_path: Path) -> None:
    with zipfile.ZipFile(
        zip_path,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=6,
    ) as zf:
        for path in ext_path.rglob("*"):
            arcname = path.relative_to(ext_path)
            if path.is_file():
                zf.write(path, arcname)

def get_extracted_size() -> int:
    # Check cache
    if SIZE_CACHE_FILE.exists():    
        with open(SIZE_CACHE_FILE, "r") as cf:
            try:
                cached = json.load(cf)
                timestamp: float = cached.get("timestamp", 0)
                extracted_size: int = cached.get("extracted_size", 0)
                # Younger than 15min
                if timestamp > time.time() - 15*60:
                    return extracted_size
            except:
                pass
    # Compute total
    total = 0
    for item in REPO_PATH.iterdir():
        if not item.is_dir(): continue
        ext_path = item / "extracted"
        if not ext_path.exists(): continue
        for child in ext_path.rglob("*"):
            if child.is_file():
                total += child.stat().st_size
    # Save to cache
    try:
        with open(SIZE_CACHE_FILE, "w") as cf:
            json.dump({"timestamp": time.time(), "extracted_size": total}, cf)
    except:
        pass
    return total

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