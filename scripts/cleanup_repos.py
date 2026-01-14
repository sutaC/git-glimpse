from pathlib import Path
import sqlite3
import shutil

PROJECT_ROOT_PATH = Path(__file__).parent.parent
DATABASE_PATH = PROJECT_ROOT_PATH / "database.db"
REPO_PATH = PROJECT_ROOT_PATH / "repo"

def remove_dir(path: Path):
    path.chmod(0o700)
    for child in path.rglob("*"):
        child.chmod(0o700)
    shutil.rmtree(path)

def main():
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

if __name__ == "__main__":
    main()