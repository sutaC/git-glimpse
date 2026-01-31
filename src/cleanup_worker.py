from dotenv import load_dotenv
load_dotenv()
# ensures loaded .env in modules
from lib.git import remove_protected_dir, RepoLock
from globals import DATABASE_PATH, REPO_PATH
from lib.database import Database
from lib.logger import log

# --- repos
def cleanup_repos(db: Database):
    log("Starting repos cleanup")
    count = 0
    for item in REPO_PATH.iterdir():
        if not item.is_dir(): continue
        user_id: int | None = db._fetch_value("SELECT `user_id` FROM `repos` WHERE `id` = ?;", (item.name,))
        if not user_id: # Repo id not in db
            remove_protected_dir(item)
            log(f"Removing repo {item} -- not existent in db")
            count += 1
            continue
        user_exists = db._fetch_exists("SELECT 1 FROM `users` WHERE `id` = ?;", (user_id,))
        if not user_exists: # Repo in db but user is not
            db._cursor().execute("DELETE FROM `repos` WHERE `user_id` = ?;", (user_id,))
            db._commit()
            remove_protected_dir(item)
            log(f"Removing repo {item} -- no user attached")
            count += 1
            continue
    log(f"Deleted {count} repos", "INFO")

# --- extracted
def cleanup_extracted():
    log("Starting extracted cleanup")
    count = 0
    for item in REPO_PATH.iterdir():
        if not item.is_dir(): continue
        ext_path = item / "extracted"
        if not ext_path.exists(): continue 
        with RepoLock(ext_path):
            if ext_path.exists():
                remove_protected_dir(ext_path)
                log(f"Removing {item}/extracted")
                count += 1
    # removes cached size
    size_cache = REPO_PATH / ".size.json"
    size_cache.unlink(missing_ok=True)
    # ---
    log(f"Deleted {count} extracted", "INFO")

# --- sessions
def cleanup_sessions(db: Database):
    log("Starting sessions cleanup")
    c = db._cursor()
    c.execute("DELETE FROM `sessions` WHERE `expires` < unixepoch();")
    db._commit()
    log(f"Deleted {c.rowcount} expired sessions", "INFO")

# --- builds
def cleanup_builds(db: Database):
    log("Starting builds cleanup")
    c = db._cursor()
    c.execute('''
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
    db._commit()
    log(f"Deleted {c.rowcount} expired builds", "INFO")

# --- main
def main():
    log("Startting cleanup worker", "INFO")
    db = Database(DATABASE_PATH, raw_mode=True)
    db.init_db()
    cleanup_repos(db)
    cleanup_extracted()
    cleanup_builds(db)
    cleanup_sessions(db)
    db._close()
    log("Closing cleanup worker", "INFO")

if __name__ == "__main__":
    main()