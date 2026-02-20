from src.globals import REPO_PATH, SIZE_CACHE_PATH
from cryptography.fernet import Fernet 
from src.lib import sections, logger as lg
from typing import Literal
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
FERNET = Fernet(_FERNET_KEY)

ARTIFACT_NAME = "artifact.tar.zst"
HTML_ARTIFACT_NAME = "html.tar.zst"
MAX_REPO_SIZE = 100 * 1024 * 1024  # 100 MB
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
MAX_FILE_COUNT = 10_000
MAX_DIR_COUNT = 5_000
MAX_DEPTH = 20
MAX_SCAN_TIME = 10 # 10 s
MAX_CLONE_TIME = 30 # 30 s
MAX_RENDER_TIME = 20 # 20 s
MAX_RENDER_FILE_SIZE = 1024 * 1024 # 1 MB

class RepoError(RuntimeError):
    def __init__(self, type: Literal['f', 'v'], code: str, **args) -> None:
        super().__init__(*args)
        self.type: Literal['f', 'v'] = type
        self.code: str = code
        self.extra = args

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
    env = os.environ.copy()
    key_path = None
    try:
        if ssh_key:
            key_path = write_ssh_key_temp(ssh_key)
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
                    timeout=MAX_CLONE_TIME
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
            repo_size = check_repo_limits(tmpdir)
            # Ensures target dir is empty
            if repo_dir.exists():
                remove_protected_dir(repo_dir)
            repo_dir.mkdir(exist_ok=True, parents=True)
            # Moves files to repo_dir artifact
            artifact_path = repo_dir / ARTIFACT_NAME
            compress_repo(tmpdir, artifact_path)
            artifact_path.chmod(0o400)
            # Renders code files
            html_artifact_path = repo_dir / HTML_ARTIFACT_NAME
            with tempfile.TemporaryDirectory() as tmpdir_html_str:
                tmpdir_html = Path(tmpdir_html_str)
                try:
                    render_repo(tmpdir, tmpdir_html)
                except TimeoutError:
                    raise RepoError('v', lg.Code.RENDER_TIMEOUT)
                compress_repo(tmpdir_html, html_artifact_path)
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

def compress_repo(src_dir: Path, archive_path: Path, compression_level: int = 3) -> None:
    with open(archive_path, "wb") as f_out:
        cctx = zstd.ZstdCompressor(level=compression_level)
        with cctx.stream_writer(f_out) as compressor:
            with tarfile.open(fileobj=compressor, mode="w") as tar:
                tar.add(src_dir, arcname="")

def extract_repo(repo_path: Path) -> None:
    if not repo_path.exists(): return None
    with RepoLock(repo_path):
        _extract_repo_artifact(artifact_path=(repo_path / ARTIFACT_NAME), dest_path=(repo_path / "extracted"))
        _extract_repo_artifact(artifact_path=(repo_path / HTML_ARTIFACT_NAME), dest_path=(repo_path / "html"))
    lg.log(lg.Event.REPO_EXTRACTED, repo_id=repo_path.name)

def _extract_repo_artifact(artifact_path: Path, dest_path: Path) -> None:
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

def remove_protected_dir(path: Path):
    if not path.exists(): return
    path.chmod(0o700)
    for child in path.rglob("*"):
        child.chmod(0o700)
    shutil.rmtree(path)

def remove_extracted_artifacts(repo_path: Path) -> bool:
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
    ext_path = repo_path / "extracted"
    html_path = repo_path / "html"
    if not ext_path.exists() or not html_path.exists():
        extract_repo(repo_path)
    path = (ext_path / sub_path).resolve()
    if not path.is_relative_to(ext_path): raise LookupError()
    if path.is_symlink() or any(p.is_symlink() for p in path.parents): raise LookupError()
    if not path.exists(): raise LookupError()
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

def get_total_repos_size() -> int:
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
        for child in repo_path.rglob("*"):
            if child.is_file():
                total += child.stat().st_size
    # Save to cache
    try:
        with open(SIZE_CACHE_PATH, "w") as cf:
            json.dump({"timestamp": time.time(), "size": total}, cf)
    except:
        pass
    return total

def encrypt_ssh_key(ssh_key: str) -> str:
    return FERNET.encrypt(ssh_key.encode()).decode()

def decrypt_ssh_key(ssh_key: str) -> str:
    return FERNET.decrypt(ssh_key.encode()).decode()

def normalize_ssh_key(ssh_key: str) -> str:
    ssh_key = ssh_key.strip().replace("\r\n", "\n").replace("\r", "\n")
    if not ssh_key.endswith("\n"):
        ssh_key += "\n"
    return ssh_key

def write_ssh_key_temp(ssh_key: str) -> Path:
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write(ssh_key)
        key_path = Path(f.name)
    key_path.chmod(0o600)
    return key_path

def check_ssh_access(key_path: str) -> bool:
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
    # lengh check
    if len(key) > 10_000:
        return "SSH key too large"
    # ssh-keygen check
    path = write_ssh_key_temp(key)
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
        if not check_ssh_access(str(path)):
            return "SSH key does not provide required permissions"
    except subprocess.TimeoutExpired:
        return "SSH key check timed out"
    except OSError:
        return "Failed to validate SSH key"
    finally:
        path.unlink(missing_ok=True)

def render_repo(src_path: Path, dest_path: Path) -> None:
    start = time.monotonic()
    for path in src_path.rglob("*"):
        if time.monotonic() - start > MAX_RENDER_TIME: 
            raise TimeoutError()
        if not path.is_file(): continue
        if not sections.is_text(path): continue
        path_size = path.stat().st_size
        if not path_size: continue
        if path_size > MAX_RENDER_FILE_SIZE: continue
        ftype = sections.detect_file_type(path)
        if ftype == "markdown":
            html = sections.render_markdown(path.read_text(errors="replace"))
        elif ftype == "code":
            html = sections.highlight_code(path.read_text(errors="replace"), path.name)
        else:
            continue
        html_path = dest_path / (str(path.relative_to(src_path)) + ".html")
        html_path.parent.mkdir(parents=True, exist_ok=True)
        html_path.write_text(html)