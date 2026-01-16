from pathlib import Path
import sqlite3
import shutil
import time

PROJECT_ROOT_PATH = Path(__file__).parent.parent
DATABASE_PATH = PROJECT_ROOT_PATH / "database.db"
REPO_PATH = PROJECT_ROOT_PATH / "repo"

# --- repos
def remove_dir(path: Path):
    path.chmod(0o700)
    for child in path.rglob("*"):
        child.chmod(0o700)
    shutil.rmtree(path)

def cleanup_repos():
    if not DATABASE_PATH.exists():
        print("Database file does not exist")
        return
    c = sqlite3.connect(DATABASE_PATH) 
    cursor = c.cursor()
    for item in REPO_PATH.iterdir():
        cursor.execute("SELECT `user_id` FROM `repos` WHERE `id` = ?;", [item.name])
        repo = cursor.fetchone()
        if not repo: # Repo id not in db
            remove_dir(item)
            print(f"Deleted repo {item.name} -- not existent in db")
            continue
        user_id: int = repo[0]
        cursor.execute("SELECT `id` FROM `users` WHERE `id` = ?;", [user_id])
        user = cursor.fetchone()
        if not user: # Repo in db but user is not
            cursor.execute("DELETE FROM `repos` WHERE `user_id` = ?;", [user_id])
            c.commit()
            remove_dir(item)
            print(f"Deleted repo {item.name} -- no user attached")
            continue
    cursor.close()
    c.close()

# --- extracted
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

def cleanup_extracted():
    for item in REPO_PATH.iterdir():
        print(f"Removing {item}/extracted")
        remove_extracted(item)

# --- sessions
def cleanup_sessions():
    if not DATABASE_PATH.exists():
        print("Database file does not exist")
        return
    now = int(time.time()) 
    with sqlite3.connect(DATABASE_PATH) as connection:
        cursor = connection.cursor()
        cursor.execute("DELETE FROM `sessions` WHERE `expires` < ?;", (now,))
        connection.commit()
        print(f"Deleted {cursor.rowcount} expired sessions")

# --- main
if __name__ == "__main__":
    cleanup_repos()
    cleanup_extracted()
    cleanup_sessions()