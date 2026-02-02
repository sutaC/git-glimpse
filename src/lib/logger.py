from datetime import datetime
import json
import os

_ENV = os.environ.get("ENV")

class Level:
    INFO = "INFO"
    DEBUG = "DEBUG"
    ERROR = "ERROR"
    WARN = "WARN"

class Event:
    # Server
    SERVER_internal_ERROR = "server.internal.error"
    # Worker
    WORKER_START = "worker.start"
    WORKER_IDLE = "worker.idle"
    WORKER_STOPPED = "worker.stopped"
    WORKER_ERROR = "worker.error"
    # Build
    BUILD_QUEUED = "build.queued"
    BUILD_CLAIMED = "build.claimed"
    BUILD_STARTED = "build.started"
    BUILD_FINISHED = "build.finished"
    BUILD_FAILED = "build.failed"
    BUILD_VIOLATION = "build.violation"
    # Cleanup
    CLEANUP_STARTED = "cleanup.started"
    CLEANUP_FINISHED = "cleanup.finished"
    # Admin
    ADMIN_USER_ROLE_CHANGE = "admin.user.role.change"
    ADMIN_USER_VERIFICATION_CHANGE = "admin.user.verification.change"
    ADMIN_USER_QUOTA_RESET = "admin.user.quota.reset"
    # Repo
    REPO_ADDED = "repo.added"
    REPO_REMOVED = "repo.removed"
    REPO_EXTRACTED = "repo.extracted"
    # Auth
    AUTH_LOGIN_SUCCESS = "auth.login.success"
    AUTH_LOGIN_FAILURE = "auth.login.failure"
    AUTH_LOGOUT = "auth.logout"
    AUTH_REGISTER = "auth.register"
    AUTH_USER_REMOVED = "auth.user.removed"
    AUTH_EMAIL_VERIFY_REQUEST = "auth.email.verify.request"
    AUTH_EMAIL_VERIFY_REQUEST_BLOCKED = "auth.email.request.blocked"
    AUTH_EMAIL_VERIFY_COMPLETE = "auth.email.verify.complete"
    AUTH_EMAIL_VERIFY_INVALID = "auth.email.verify.invalid"
    AUTH_PASSWORD_RECOVERY_REQUEST = "auth.password.recovery.request"
    AUTH_PASSWORD_RECOVERY_REQUEST_BLOCKED = "auth.password.recovery.request.blocked"
    AUTH_PASSWORD_RECOVERY_REQUEST_INVALID = "auth.password.recovery.request.invalid"
    AUTH_PASSWORD_RESET_SUCCESS = "auth.password.reset.success"
    AUTH_PASSWORD_RESET_INVALID = "auth.password.reset.invalid"
    AUTH_PASSWORD_CHANGE_FAILURE = "auth.password.change.failure"
    AUTH_PASSWORD_CHANGE_SUCCESS = "auth.password.change.success"
    # Emails
    EMAIL_SEND = "email.send"
    EMAIL_SEND_FAILED = "email.send.failed"

class Code:
    LIMIT_MAX_SIZE = "LIMIT_MAX_SIZE"
    LIMIT_MAX_FILE = "LIMIT_MAX_FILE"
    LIMIT_MAX_FILES = "LIMIT_MAX_FILES"
    LIMIT_MAX_DIRS = "LIMIT_MAX_DIRS"
    LIMIT_MAX_DEPTH = "LIMIT_MAX_DEPTH"
    FORBIDDEN_FILE_TYPE = "FORBIDDEN_FILE_TYPE"
    SCAN_TIMEOUT = "SCAN_TIMEOUT"
    CLONE_TIMEOUT = "CLONE_TIMEOUT"
    BUILD_EXCEPTION = "BUILD_EXCEPTION"
    REPO_LOCK_ACQUISITION = "REPO_LOCK_AQUISITION"
    REPO_NOT_FOUND = "REPO_NOT_FOUND"
    USER_NOT_FOUND = "USER_NOT_FOUND"
    INVALID_PASSWORD = "INVALID_PASSWORD"

USER_MESSAGES = {
    Code.LIMIT_MAX_SIZE: "Repository exceeds 100 MB limit",
    Code.LIMIT_MAX_FILE: "One of your files exceeds 10 MB limit",
    Code.LIMIT_MAX_FILES: "Repository contains more than 10,000 files",
    Code.LIMIT_MAX_DIRS: "Repository contains more than 5,000 directories",
    Code.LIMIT_MAX_DEPTH: "Repository exceeds maximum directory depth of 20",
    Code.FORBIDDEN_FILE_TYPE: "Repository contains forbidden file type(s)",
    Code.SCAN_TIMEOUT: "Repository scanning exceeded 10 seconds",
    Code.CLONE_TIMEOUT: "Repository cloning exceeded 30 seconds",
    Code.BUILD_EXCEPTION: "Build failed due to an unexpected error",
    Code.REPO_LOCK_ACQUISITION: "Could not acquire repository lock. Try again later",
    Code.REPO_NOT_FOUND: "Repository data was not found"
}

DEFAULT_LEVELS = {
    Code.LIMIT_MAX_SIZE: "WARN",
    Code.LIMIT_MAX_FILE: "WARN",
    Code.LIMIT_MAX_FILES: "WARN",
    Code.LIMIT_MAX_DIRS: "WARN",
    Code.LIMIT_MAX_DEPTH: "WARN",
    Code.FORBIDDEN_FILE_TYPE: "WARN",
    Code.SCAN_TIMEOUT: "ERROR",
    Code.CLONE_TIMEOUT: "ERROR",
    Code.BUILD_EXCEPTION: "ERROR",
    Code.REPO_LOCK_ACQUISITION: "ERROR"
}

def log(
    event: str, 
    level: str = "INFO", 
    code: str | None = None,
    build_id: int | None = None,
    repo_id: str | None = None,
    user_id: int | None = None,
    extra = None
    ) -> None:
    if _ENV == 'prod' and level == Level.DEBUG: return
    entry = {
        "ts": datetime.now().isoformat(),
        "level": level,
        "event": event
    }
    if code:
        entry["code"] = code
        entry["msg"] = USER_MESSAGES.get(code, "")
    if user_id: entry["user_id"] = str(user_id)
    if repo_id: entry["repo_id"] = repo_id
    if build_id: entry["build_id"] = str(build_id)
    if extra: entry.update(extra)
    print(json.dumps(entry))
