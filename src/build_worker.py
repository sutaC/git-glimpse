from dotenv import load_dotenv
load_dotenv()
# ensures loaded .env in modules
from globals import DATABASE_PATH, REPO_PATH
from lib.database import Database
import lib.logger as lg
from time import sleep, time
import lib.git as git


def main():
    db = Database(DATABASE_PATH, raw_mode=True)
    db.init_db()
    lg.log(lg.Event.WORKER_START)
    db.resurect_running_builds()
    prev_idle = False
    while True:
        build = db.get_pending_build()
        if not build:
            db._close() # to not hold db on sleeping
            if not prev_idle:
                prev_idle = True
                lg.log(lg.Event.WORKER_IDLE)
            sleep(5)
            continue
        prev_idle = False
        lg.log(lg.Event.BUILD_CLAIMED, build_id=build.id)
        ts_start = time()
        repo = db.get_repo_for_clone(build.repo_id)
        if not repo:
            db.update_build(build.id, 'f')
            lg.log(lg.Event.BUILD_FAILED, lg.Level.ERROR, lg.Code.REPO_NOT_FOUND, build_id=build.id, repo_id=build.repo_id)
            continue
        db._close() # to not hold db on long clones
        path = REPO_PATH / build.repo_id
        ssh_key_plain = git.decrypt_ssh_key(repo.ssh_key) if repo.ssh_key else None
        repo_size = None
        archive_size = None
        lg.log(lg.Event.BUILD_STARTED, build_id=build.id, repo_id=build.repo_id, user_id=repo.user_id)
        try:
            repo_size, archive_size = git.clone_repo(repo.url, path, ssh_key_plain)
        except git.RepoError as re:
            db.update_build(build.id, re.type, code=re.code)
            git.remove_protected_dir(path)
            db.set_repo_hidden(build.repo_id, True)
            ts_end = time()
            if re.type == 'f': 
                lg.log(
                    lg.Event.BUILD_FAILED, 
                    lg.DEFAULT_LEVELS.get(re.code, lg.Level.ERROR), 
                    re.code, build.id, build.repo_id, repo.user_id,
                    {"duration": int((ts_end-ts_start)*1000)}
                )
                continue
            elif re.type == 'v': 
                lg.log(
                    lg.Event.BUILD_VIOLATION, 
                    lg.DEFAULT_LEVELS.get(re.code, lg.Level.WARN), 
                    re.code, build.id, build.repo_id, repo.user_id,
                    {"duration": int((ts_end-ts_start)*1000)}
                )
                continue
        db.update_build(build.id, 's', repo_size, archive_size)
        db.set_repo_hidden(build.repo_id, False)
        ts_end = time()
        lg.log(
            lg.Event.BUILD_FINISHED, 
            build_id=build.id, repo_id=build.repo_id, user_id=repo.user_id, 
            extra={"duration": int((ts_end-ts_start)*1000)}
        )

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        lg.log(lg.Event.WORKER_STOPPED)
    except Exception as e:
        lg.log(lg.Event.WORKER_ERROR, lg.Level.ERROR, extra={"reason": str(e)})