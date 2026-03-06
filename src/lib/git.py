"""Module provides interface for handing git repositories."""
from src.globals import REPO_PATH, SIZE_CACHE_PATH
from src.lib import render, logger as lg
from cryptography.fernet import Fernet 
from typing import Literal
from hashlib import sha256
from pathlib import Path
import zstandard as zstd
import subprocess
import tempfile
import tarfile
import zipfile
import shutil
import time
import json
import os

_FERNET_KEY = os.environ.get("FERNET_KEY", "")
if not _FERNET_KEY: raise SystemError("FERNET_KEY env is required.")
_FERNET = Fernet(_FERNET_KEY)

_ARTIFACT_NAME = "artifact.tar.zst"
_HTML_ARTIFACT_NAME = "html.tar.zst"
_MAX_REPO_SIZE = 100 * 1024 * 1024  # 100 MB
_MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
_MAX_FILE_COUNT = 10_000
_MAX_DIR_COUNT = 5_000
_MAX_DEPTH = 20
_MAX_SCAN_TIME = 10 # 10 s
_MAX_CLONE_TIME = 30 # 30 s
_MAX_RENDER_TIME = 20 # 20 s
_MAX_RENDER_FILE_SIZE = 1024 * 1024 # 1 MB

class RepoError(RuntimeError):
    """Repository cloning error.
    
    Types of RepoError:
    - 'f' = failure 
    - 'v' = violation

    Args:
        type: Type of error.
        code: Error code corresponding to `lib.logger.Code`.
        args: Additional error information.
    """
    def __init__(self, type: Literal['f', 'v'], code: str, **args) -> None:
        super().__init__(*args)
        self.type: Literal['f', 'v'] = type
        self.code: str = code
        self.extra = args

class RepoLockError(RuntimeError):
    """Repository lock error."""

    def __init__(self, *args: object) -> None:
        super().__init__(*args)

class RepoLock:
    """Repository lock for asyncronus repo managment.
    
    Args:
        repo_path: Path to repository.
    """

    def __init__(self, repo_path: Path) -> None:
        self.lock_file = repo_path / ".extract.lock"
        self.acquired = False

    def acquire(self, timeout: int = 10) -> None:
        """Acquires lock.
        
        Args:
            timeout: Timeout for aquiring repo lock in seconds (default 10).

        Raises:
            RepoLockError: When repository lock could not be aquired. 
        """
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
                    raise RepoLockError("Could not acquire repo lock")
                time.sleep(0.1)

    def release(self) -> None:
        """Releases repository lock."""
        if self.acquired and self.lock_file.exists():
            self.lock_file.unlink()
            self.acquired = False

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.release()

# --- repo cloning ---
def _check_repo_limits(path: Path) -> int:
    """Scans repository and validates limits.
    
    Args:
        path: Repository path.

    Returns:
        Total repository size.

    Raises:
        RepoError: When repositroy violates limits.
    """
    total_size = 0
    file_count = 0
    dir_count = 0
    time_limit = time.monotonic()
    for f in path.rglob("*"):
        if f.is_file():
            if time.monotonic() - time_limit > _MAX_SCAN_TIME:
                raise RepoError('v', lg.Code.SCAN_TIMEOUT)
            file_count += 1
            if file_count > _MAX_FILE_COUNT:
                raise RepoError('v', lg.Code.LIMIT_MAX_FILES)
            size = f.stat().st_size
            if size > _MAX_FILE_SIZE:
                raise RepoError('v', lg.Code.LIMIT_MAX_FILE)
            total_size += size
            if total_size > _MAX_REPO_SIZE:
                raise RepoError('v', lg.Code.LIMIT_MAX_SIZE)
        if f.is_dir():
            dir_count += 1
            if dir_count > _MAX_DIR_COUNT:
                raise RepoError('v', lg.Code.LIMIT_MAX_DIRS)
            depth = len(f.relative_to(path).parts)
            if depth > _MAX_DEPTH:
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
    """Clones repository.
    
    Args:
        url: Repository URL.
        repo_dir: Repository destination path (eg. `.../data/repos/[id]/`).
        ssh_key: Repository SSH key (only when using SSH URL).
    
    Returns:
        Repository total size, repository artifact size.

    Raises:
        RepoError: When clone fails unexpectedly or repository violates rules.
    """
    env = os.environ.copy()
    key_path = None
    try:
        if ssh_key:
            key_path = _write_ssh_key_temp(ssh_key)
            env["GIT_SSH_COMMAND"] = f"\
                ssh -i {key_path} \
                    -o StrictHostKeyChecking=yes \
                    -o IdentitiesOnly=yes \
                    -o UserKnownHostsFile=/home/appuser/.ssh/known_hosts \
            "
        with tempfile.TemporaryDirectory() as tmpdir_str:
            tmpdir = Path(tmpdir_str)
            try:
                result = subprocess.run([
                        "git", "clone", 
                        "--depth", "1",
                        "--single-branch",
                        "--no-tags",
                        "--no-recurse-submodules",
                        url, str(tmpdir)
                    ],
                    capture_output=True,
                    text=True,
                    env=env,
                    timeout=_MAX_CLONE_TIME
                )
            except subprocess.TimeoutExpired:
                raise RepoError('v', lg.Code.CLONE_TIMEOUT)
            except OSError as e:
                raise RepoError('f', lg.Code.BUILD_EXCEPTION, reason=e.strerror)
            # Clone errors
            if result.returncode != 0:
                stderr = result.stderr.lower()
                if "permission denied" in stderr:
                    raise RepoError('f', lg.Code.REPO_PERMISSION_DENIED)
                elif "repository not found" in stderr:
                    raise RepoError('f', lg.Code.REPO_NOT_FOUND)
                elif "could not resolve host" in stderr or "connection timed out" in stderr:
                    raise RepoError('f', lg.Code.NETWORK_ERROR)
                else:
                    raise RepoError('f', lg.Code.BUILD_EXCEPTION)
            # Removes git
            git_dir = tmpdir / ".git"
            if git_dir.is_dir(): shutil.rmtree(git_dir, ignore_errors=True)
            # Checks git modules
            gitmodules_dir = tmpdir / ".gitmodules"
            if gitmodules_dir.exists(): 
                raise RepoError('v', lg.Code.FORBIDDEN_FILE_TYPE)
            # Checks repo limits
            repo_size = _check_repo_limits(tmpdir)
            # Ensures target dir is empty
            if repo_dir.exists():
                remove_protected_dir(repo_dir)
            repo_dir.mkdir(exist_ok=True, parents=True)
            # Moves files to repo_dir artifact
            artifact_path = repo_dir / _ARTIFACT_NAME
            _compress_dir(tmpdir, artifact_path)
            artifact_path.chmod(0o400)
            # Renders code files
            html_artifact_path = repo_dir / _HTML_ARTIFACT_NAME
            with tempfile.TemporaryDirectory() as tmpdir_html_str:
                tmpdir_html = Path(tmpdir_html_str)
                try:
                    _render_repo(tmpdir, tmpdir_html)
                except TimeoutError:
                    raise RepoError('v', lg.Code.RENDER_TIMEOUT)
                _compress_dir(tmpdir_html, html_artifact_path)
            html_artifact_path.chmod(0o400)
            # returns repo size
            artifact_sizes = artifact_path.stat().st_size + html_artifact_path.stat().st_size
            return repo_size, artifact_sizes
    except RepoError:
        raise # pass RepoErorrs
    except Exception as e:
        raise RepoError('f', lg.Code.BUILD_EXCEPTION, reason=str(e))
    finally:
        if key_path: key_path.unlink(missing_ok=True)

def _compress_dir(src_dir: Path, archive_path: Path, compression_level: int = 3) -> None:
    """Compresses src directory to `.zst.tar` archive.
    
    Args:
        src_dir: Source directory to compress.
        archive_path: Path where archive will be written.
        compression_level: Zst compression level (default 4). 
    """
    with open(archive_path, "wb") as f_out:
        cctx = zstd.ZstdCompressor(level=compression_level)
        with cctx.stream_writer(f_out) as compressor:
            with tarfile.open(fileobj=compressor, mode="w") as tar:
                tar.add(src_dir, arcname="")

def _render_repo(src_path: Path, dest_path: Path) -> None:
    """Prerenders repository files.

    Args:
        src_path: Repository source path.
        dest_path: Destination folder path (will be modified).
    
    Raises:
        TimeoutError: When reaches render timeout.
    """
    start = time.monotonic()
    for path in src_path.rglob("*"):
        if time.monotonic() - start > _MAX_RENDER_TIME: 
            raise TimeoutError()
        if not path.is_file(): continue
        if not render.is_text(path): continue
        path_size = path.stat().st_size
        if not path_size: continue
        if path_size > _MAX_RENDER_FILE_SIZE: continue
        ftype = render.detect_file_type(path)
        if ftype == "markdown":
            html = render.render_markdown(path.read_text(errors="replace"))
        elif ftype == "code":
            html = render.render_code(path.read_text(errors="replace"), path.name)
        else:
            continue
        html_path = dest_path / (str(path.relative_to(src_path)) + ".html")
        html_path.parent.mkdir(parents=True, exist_ok=True)
        html_path.write_text(html)

# --- repo handling ---
def _extract_repo(repo_path: Path) -> None:
    """Extracts all repository artifact.

    **Warning:** This function uses `RepoLock`.

    Extarcts repositroy artifacts to:
    - `extracted/` = Regular files
    - `html/` = Prerendered template files
    
    Args:
        repo_path: Path to repository.

    Raises:
        RepoLockError: If repository lock could not be acquired.
    """
    if not repo_path.exists(): return None
    with RepoLock(repo_path):
        _extract_repo_artifact(artifact_path=(repo_path / _ARTIFACT_NAME), dest_path=(repo_path / "extracted"))
        _extract_repo_artifact(artifact_path=(repo_path / _HTML_ARTIFACT_NAME), dest_path=(repo_path / "html"))
    lg.log(lg.Event.REPO_EXTRACTED, repo_id=repo_path.name)

def _extract_repo_artifact(artifact_path: Path, dest_path: Path) -> None:
    """Extarcs specific repository artifact.
    
    **Warning:** This function operates on repository files and should be used with `RepoLock`.

    Args:
        artifact_path: Repository artifact file path.
        dest_path: Destination path.
    """
    if not artifact_path.exists(): raise FileNotFoundError("Artifact doesnt exist")
    if dest_path.exists(): remove_protected_dir(dest_path)
    dest_path.mkdir(parents=True)
    with tempfile.TemporaryDirectory() as tmpdir_str:
        tmpdir = Path(tmpdir_str)
        with open(artifact_path, "rb") as f:
            dctx = zstd.ZstdDecompressor()
            with dctx.stream_reader(f) as reader:
                with tarfile.open(fileobj=reader, mode="r|*") as tar: # stream mode
                    for member in tar:
                        if member.islnk() or member.issym():
                            raise RuntimeError(f"Symlinks/hardlinks are not allowed: {member.name}")
                        if member.isdev() or member.isfifo():
                            raise RuntimeError(f"Unsupported device in artifact: {member.name}")
                        tar.extract(member, path=tmpdir, numeric_owner=False)
        # Move from temp dir
        for item in tmpdir.iterdir():
                shutil.move(item, dest_path)
    # Permissons restrictions
    for path in dest_path.rglob("*"):
        if path.is_file():
            path.chmod(0o400)
        elif path.is_dir():
            path.chmod(0o500)

def remove_protected_dir(path: Path) -> None:
    """Removes repository protected directories.

    **Warning:** If this function operates on repository files you should be using `RepoLock`.

    Args:
        path: Directory path to remove.
    """
    if not path.exists(): return
    path.chmod(0o700)
    for child in path.rglob("*"):
        child.chmod(0o700)
    shutil.rmtree(path)

def remove_extracted_artifacts(repo_path: Path) -> bool:
    """Removes extracted repository artifacts.

    **Warning:** This function uses `RepoLock`.

    Args:
        repo_path: Path to repository.

    Returns:
        True if any one of extarcted artifacts was removed.

    Raises:
        RepoLockError: If repository lock could not be acquired.
    """
    ext_path = repo_path / "extracted"
    html_path = repo_path / "html"
    if not (ext_path.exists() or html_path.exists()):
        return False
    with RepoLock(repo_path):
        if ext_path.exists():
            remove_protected_dir(ext_path)
        if html_path.exists():
            remove_protected_dir(html_path)
    return True

def get_repo_path(repo_path: Path, sub_path: Path) -> Path:
    """Gives absolute path to repository resource.
    
    Args:
        repo_path: Path to repository.
        sub_path: Inner repository path.

    Returns:
        Absolute path to repository resource

    Raises:
        LookupError: If resource is not found or path is invalid.
    """
    ext_path = repo_path / "extracted"
    if not ext_path.exists() or not (repo_path / "html").exists():
        try: 
            _extract_repo(repo_path)
        except FileNotFoundError:
            lg.log(lg.Event.SERVER_INTERNAL_ERROR, lg.Level.ERROR, lg.Code.MISSING_ARTIFACT_ERROR, repo_id=repo_path.name)
            raise LookupError()
    path = (ext_path / sub_path).resolve()
    if not path.is_relative_to(ext_path): raise LookupError()
    if path.is_symlink() or any(p.is_symlink() for p in path.parents): raise LookupError()
    if not path.exists(): raise LookupError()
    return path

def zip_dir(src_path: Path, dest_path: Path) -> str:
    """Packs directory into zip archive.

    **Warning:** If this function operates on repository files you should be using `RepoLock`.

    Args:
        src_path: Source directory to pack.
        dest_path: Destination path where zip archive is written to.

    Returns:
        Zip hash.
    """
    with zipfile.ZipFile(
        dest_path,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=6,
    ) as zf:
        for path in src_path.rglob("*"):
            arcname = path.relative_to(src_path)
            if path.is_file():
                zf.write(path, arcname)
    return sha256(dest_path.read_bytes()).hexdigest()

def get_total_repos_size() -> int:
    """Calculates total repositories size.

    This function uses cache file stored in `data/` valid for 15 minutes.
    
    Returns:
        Total size of all repositories.
    """
    # Check cache
    if SIZE_CACHE_PATH.exists():    
        with open(SIZE_CACHE_PATH, "r") as cf:
            try:
                cached = json.load(cf)
                timestamp: float = cached.get("timestamp", 0)
                size: int = cached.get("size", 0)
                # Younger than 15min
                if timestamp > time.time() - 15*60:
                    return size
            except:
                pass
    # Compute total
    total = 0
    for repo_path in REPO_PATH.iterdir():
        if not repo_path.is_dir(): continue
        try:
            with RepoLock(repo_path):
                for child in repo_path.rglob("*"):
                    if child.is_file():
                        total += child.stat().st_size
        except RepoLockError: continue
    # Save to cache
    try:
        with open(SIZE_CACHE_PATH, "w") as cf:
            json.dump({"timestamp": time.time(), "size": total}, cf)
    except:
        pass
    return total

# --- SSH key handing ---
def encrypt_ssh_key(ssh_key: str) -> str:
    """Encrypts SSH key.
    
    Args:
        ssh_key: SSH key to encrypt.

    Returns:
        Encrypted SSH key.
    """
    return _FERNET.encrypt(ssh_key.encode()).decode()

def decrypt_ssh_key(ssh_key: str) -> str:
    """Decrypts SSH key.
    
    Args:
        ssh_key: SSH key to encrypt.

    Returns:
        Decrypted SSH key.
    """
    return _FERNET.decrypt(ssh_key.encode()).decode()

def normalize_ssh_key(ssh_key: str) -> str:
    """Normalizes SSH key.
    
    Args:
        ssh_key: SSH key to normalize.

    Returns:
        Normalized SSH key.
    """
    ssh_key = ssh_key.strip().replace("\r\n", "\n").replace("\r", "\n")
    if not ssh_key.endswith("\n"):
        ssh_key += "\n"
    return ssh_key

def _write_ssh_key_temp(ssh_key: str) -> Path:
    """Writes SSH key to temporary file.

    **Warning:** Temporary file will not be automaticaly deleted.
    
    Args:
        ssh_key: SSH key to write (plain text).

    Returns:
        Path to SSH key temporary file.
    """
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write(ssh_key)
        key_path = Path(f.name)
    key_path.chmod(0o600)
    return key_path

def _check_ssh_access(key_path: str) -> bool:
    """Checks SSH access.
    
    Args:
        key_path: Path to SSH key file.
    
    Returns:
        True if SSH access is valid.
    """
    result = subprocess.run(
        [
            "ssh",
            "-i", key_path,
            "-o", "IdentitiesOnly=yes",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", "UserKnownHostsFile=/home/appuser/.ssh/known_hosts",
            "git@github.com"
        ],
        capture_output=True,
        text=True,
        timeout=5
    )
    return "successfully authenticated" in result.stdout + result.stderr

def validate_ssh_key(key: str) -> str | None:
    """Validates SSH key.
    
    Args:
        key: SSH key to validate (plain text).

    Returns:
        None if valid otherwise str validation error. 
    """
    # lengh check
    if len(key) > 10_000:
        return "SSH key too large"
    # ssh-keygen check
    path = _write_ssh_key_temp(key)
    try:
        # check structure
        try:
            subprocess.run(
                ["ssh-keygen", "-l", "-f", str(path)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                timeout=5
            )
        except subprocess.CalledProcessError:
            return "SSH key is invalid"
        # check if not encrypted 
        try:
            subprocess.run(
                ["ssh-keygen", "-y", "-f", str(path)],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                timeout=5
            )
        except subprocess.CalledProcessError:
            return "SSH key is encrypted"
        # check access
        if not _check_ssh_access(str(path)):
            return "SSH key does not provide required permissions"
    except subprocess.TimeoutExpired:
        return "SSH key check timed out"
    except OSError:
        return "Failed to validate SSH key"
    finally:
        path.unlink(missing_ok=True)
