from pathlib import Path
import shutil
import time

PROJECT_ROOT_PATH = Path(__file__).parent.parent 
REPO_PATH =  PROJECT_ROOT_PATH / "repo"

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

def remove_protected_dir(path: Path):
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

def main():
    for item in REPO_PATH.iterdir():
        print(f"Removing {item}/extracted")
        remove_extracted(item)

if __name__ == "__main__":
    main()