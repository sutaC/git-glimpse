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
    print("# Starting repos cleanup")
    if not DATABASE_PATH.exists():
        print("Database file does not exist -- omitting repos cleanup")
        return
    c = sqlite3.connect(DATABASE_PATH) 
    cursor = c.cursor()
    count = 0
    for item in REPO_PATH.iterdir():
        cursor.execute("SELECT `user_id` FROM `repos` WHERE `id` = ?;", [item.name])
        repo = cursor.fetchone()
        if not repo: # Repo id not in db
            remove_dir(item)
            print(f"Deleted repo {item.name} -- not existent in db")
            count += 1
            continue
        user_id: int = repo[0]
        cursor.execute("SELECT `id` FROM `users` WHERE `id` = ?;", [user_id])
        user = cursor.fetchone()
        if not user: # Repo in db but user is not
            cursor.execute("DELETE FROM `repos` WHERE `user_id` = ?;", [user_id])
            c.commit()
            remove_dir(item)
            print(f"Deleted repo {item.name} -- no user attached")
            count += 1
            continue
    cursor.close()
    c.close()
    print(f"Deleted {count} repos")


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
    print("# Starting extracted cleanup")
    count = 0
    for item in REPO_PATH.iterdir():
        print(f"Removing {item}/extracted")
        remove_extracted(item)
        count += 1
    print(f"Deleted {count} extracted")
    

# --- sessions
def cleanup_sessions():
    print("# Starting sessions cleanup")
    if not DATABASE_PATH.exists():
        print("Database file does not exist -- omitting sessions cleanup")
        return
    with sqlite3.connect(DATABASE_PATH) as connection:
        cursor = connection.cursor()
        cursor.execute("DELETE FROM `sessions` WHERE `expires` < unixepoch();")
        connection.commit()
        print(f"Deleted {cursor.rowcount} expired sessions")

# --- builds
def cleanup_builds():
    print("# Starting builds cleanup")
    if not DATABASE_PATH.exists():
        print("Database file does not exist -- omitting builds cleanup")
        return
    with sqlite3.connect(DATABASE_PATH) as connection:
        cursor = connection.cursor()
        cursor.execute('''
                DELETE FROM `builds`
                WHERE `id` in (
                    SELECT `b`.`id` 
                    FROM `builds` AS `b`
                    LEFT JOIN `repos` AS `r` ON `r`.`id` = `b`.`repo_id`
                    WHERE `b`.`timestamp` < unixepoch() - 7*24*3600
                    AND (
                        -- orphaned build
                        `r`.`id` is NULL
                        OR
                        -- not latest build for repo
                        `b`.`id` != (
                            SELECT `id` FROM `builds` AS `b2`
                            WHERE `b2`.`repo_id` = `b`.`repo_id`
                            ORDER BY `b2`.`timestamp` DESC, `b2`.`id`
                            LIMIT 1
                        )
                    )
                )
        ''')
        connection.commit()
        print(f"Deleted {cursor.rowcount} expired builds")

# --- main
if __name__ == "__main__":
    cleanup_repos()
    cleanup_extracted()
    cleanup_sessions()
    cleanup_builds()