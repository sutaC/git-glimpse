from dotenv import load_dotenv
load_dotenv()
# ensures loaded .env in modules
from lib.database import Database
from datetime import datetime
from time import sleep
from pathlib import Path
import lib.git as git

PROJECT_ROOT = Path(__file__).parent.parent
DATABASE_PATH = PROJECT_ROOT / 'database.db'
REPO_PATH = PROJECT_ROOT / 'repo'

def log(msg: str, type: str = "INFO"):
    print(f"{datetime.now().isoformat()} :: {type} :: {msg}")

def main():
    db = Database(DATABASE_PATH, raw_mode=True)
    log("Initializing build worker")
    db.resurect_running_builds()
    while True:
        build = db.get_pending_build()
        if not build:
            db._close() # to not hold db on sleeping
            log("No pending build found, sleeping for 5s")
            sleep(5)
            continue
        log(f"Currently starting build {build.id}")
        repo = db.get_repo_for_clone(build.repo_id)
        if not repo:
            db.update_build(build.id, 'f')
            log(f"Repo not found for build {build.id}", "FAILURE")
            continue
        db._close() # to not hold db on long clones
        path = REPO_PATH / build.repo_id
        ssh_key_plain = git.decrypt_ssh_key(repo.ssh_key) if repo.ssh_key else None
        repo_size = None
        archive_size = None
        try:
            repo_size, archive_size = git.clone_repo(repo.url, path, ssh_key_plain)
        except git.RepoError as re:
            db.update_build(build.id, re.type)
            git.remove_protected_dir(path)
            if re.type == 'f': 
                log(f"Build failed: {re.msg}", "FAILURE")
                continue
            elif re.type == 'v': 
                log(f"Build detected violation of rules: {re.msg}", "VALIDATION")
                continue
        db.update_build(build.id, 's', repo_size, archive_size)
        log(f"Finished build {build.id}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("Closing build worker")