from dotenv import load_dotenv
load_dotenv()
# ensures loaded .env in modules
from src.lib.git import remove_protected_dir, RepoLock
from src.globals import CLEANUP_CACHE_PATH, DATABASE_PATH, REPO_PATH, SIZE_CACHE_PATH
from src.lib.utils import timestamp_to_str
from src.lib import emails, logger as lg
from src.lib.database import Database
from typing import NamedTuple
from time import time
import json

# --- repos
def cleanup_repos(db: Database) -> int:
    count = 0
    for item in REPO_PATH.iterdir():
        if not item.is_dir(): continue
        user_id: int | None = db._fetch_value("SELECT `user_id` FROM `repos` WHERE `id` = ?;", (item.name,))
        if not user_id: # Repo id not in db
            remove_protected_dir(item)
            count += 1
            continue
        user_exists = db._fetch_exists("SELECT 1 FROM `users` WHERE `id` = ?;", (user_id,))
        if not user_exists: # Repo in db but user is not
            db._cursor().execute("DELETE FROM `repos` WHERE `user_id` = ?;", (user_id,))
            db._commit()
            remove_protected_dir(item)
            count += 1
            continue
    return count

# --- extracted
def cleanup_extracted() -> int:
    count = 0
    for item in REPO_PATH.iterdir():
        if not item.is_dir(): continue
        ext_path = item / "extracted"
        if not ext_path.exists(): continue 
        with RepoLock(ext_path):
            if ext_path.exists():
                remove_protected_dir(ext_path)
                count += 1
    # removes cached size
    SIZE_CACHE_PATH.unlink(missing_ok=True)
    return count

# --- sessions
def cleanup_sessions(db: Database) -> int:
    c = db._cursor()
    c.execute("DELETE FROM `sessions` WHERE `expires` < unixepoch();")
    db._commit()
    return c.rowcount

# --- tokens
def cleanup_tokens(db: Database) -> int:
    c = db._cursor()
    c.execute("DELETE FROM `tokens` WHERE `expires` < unixepoch();")
    db._commit()
    return c.rowcount

# --- builds
def cleanup_builds(db: Database) -> int:
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
    return c.rowcount

# --- repo views
def cleanup_repo_views(db: Database) -> int:
    c = db._cursor()
    cday = int(time() / 86400)
    c.execute('DELETE FROM `repo_views` WHERE `day` < ? - 30;', (cday,))
    db._commit()
    return c.rowcount

# --- inactive users
def flag_inactive_users(db: Database) -> int:
    c = db._cursor()
    users = c.execute('''
        SELECT `id`, `is_verified`, `email`, `login`, `last_login` FROM `users` 
        WHERE `inactive` = 0 
        AND `last_login` < unixepoch() - 7776000 -- 90 days
        AND `login` != 'root'
    ''').fetchall()
    c.execute('''
        UPDATE `users`
        SET `inactive` = 1
        WHERE `inactive` = 0
        AND `last_login` < unixepoch() - 7776000 -- 90 days
        AND `login` != 'root'
    ''')
    db._commit()
    c.close()
    for uid, is_verified, email, login, last_login in users:
        if not is_verified: continue
        emails.send_email(
            emails.EmailIntent.INACTIVE_ACCOUNT,
            to=email,
            user_id=uid,
            is_verified=is_verified,
            user=login,
            last_login=timestamp_to_str(last_login)
        )
    return len(users)

def cleanup_inactive_users_repos(db: Database) -> int:
    c = db._cursor()
    users = c.execute('''
        SELECT `id`, `is_verified`, `email`, `login`
        FROM `users` 
        WHERE `inactive` = 1
        AND `last_login` < unixepoch() - 8380800 -- 97 days
        AND `login` != 'root'
    ''').fetchall()
    count = 0
    for uid, is_verified, email, login in users:
        repos = c.execute('SELECT `id` FROM `repos` WHERE `user_id` = ? AND `hidden` = 0;', (uid,)).fetchall()
        if not repos: continue
        count += len(repos)
        c.execute('UPDATE `repos` SET `hidden` = 1 WHERE `user_id` = ? AND `hidden` = 0;', (uid,))
        for rid in repos:
            rpath = REPO_PATH / rid[0]
            remove_protected_dir(rpath)
        if not is_verified: continue
        emails.send_email(
            emails.EmailIntent.REPO_REMOVAL,
            to=email,
            user_id=uid,
            is_verified=is_verified,
            user=login
        )
    db._commit()
    return count

# Save data
class CleanupData(NamedTuple):
    satarted: str
    duration: int
    cl_repos: int 
    cl_extracted: int
    cl_builds: int
    cl_session: int
    cl_tokens: int
    cl_repo_views: int
    cl_flag_inactive_users: int
    cl_inactive_users_repos: int

def get_last_cleanup() -> CleanupData | None:
    if not CLEANUP_CACHE_PATH.exists(): return None
    try:
        with open(CLEANUP_CACHE_PATH, "r") as cf:
            data = json.load(cf)
            return CleanupData(*data.values())
    except: return None

# --- main
def main():
    try:
        ts_start = time()
        lg.log(lg.Event.CLEANUP_STARTED)
        db = Database(DATABASE_PATH, raw_mode=True)
        db.init_db()
        cl_repos = cleanup_repos(db)
        cl_extracted = cleanup_extracted()
        cl_builds = cleanup_builds(db)
        cl_sessions = cleanup_sessions(db)
        cl_tokens = cleanup_tokens(db)
        cl_repo_views = cleanup_repo_views(db)
        cl_inactive_users_repos = cleanup_inactive_users_repos(db)
        cl_flag_inactive_users = flag_inactive_users(db)
        db._close()
        ts_end = time()
        duration = int((ts_end-ts_start)*1000)
        # Saves last cleanup data to file
        try:
            with open(CLEANUP_CACHE_PATH, "w") as cf:
                json.dump({
                    "satarted": timestamp_to_str(int(ts_start)),
                    "duration": duration,
                    "cl_repos": cl_repos,
                    "cl_extracted": cl_extracted,
                    "cl_builds": cl_builds,
                    "cl_sessions": cl_sessions,
                    "cl_tokens": cl_tokens,
                    "cl_repo_views": cl_repo_views,
                    "cl_flag_inactive_users": cl_flag_inactive_users,
                    "cl_inactive_users_repos": cl_inactive_users_repos
                }, cf)
        except: pass
        lg.log(
            lg.Event.CLEANUP_FINISHED, 
            extra={
                "duration": duration,
                "cl_repos": cl_repos, 
                "cl_extracted": cl_extracted,
                "cl_builds": cl_builds,
                "cl_sessions": cl_sessions,
                "cl_tokens": cl_tokens,
                "cl_repo_views": cl_repo_views,
                "cl_flag_inactive_users": cl_flag_inactive_users,
                "cl_inactive_users_repos": cl_inactive_users_repos
            }
        )
    except Exception:
        lg.log(lg.Event.CLEANUP_FAILED, lg.Level.ERROR)

if __name__ == "__main__":
    main()