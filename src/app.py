from flask import Flask, Response, render_template, abort, redirect, send_file, request, g
from src.lib import emails, utils, auth, git, logger as lg
from src.globals import REPO_PATH, DATABASE_PATH
from tempfile import NamedTemporaryFile
from src.lib.database import Database
from dotenv import load_dotenv
from pathlib import Path
import src.cleanup_worker as cworker
import time
import os

load_dotenv()

CONTACT_EMAIL = os.environ.get("CONTACT_EMAIL")
ERROR_PAGE_TITLES = {
    403: "Forbidden",
    404: "Page Not Found",
    500: "Internal Server Error"
}

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")

db = Database(DATABASE_PATH)
with app.app_context():
    db.init_db()

# --- request handlers
@app.teardown_appcontext
def db_close(error=None):
    db._close()

@app.before_request
def load_user():
    g.clear_session_cookie = False
    g.user = None
    session_id = request.cookies.get("session_id")
    if not session_id: return
    session = db.get_session(session_id)
    if not session: return
    if session.expires < int(time.time()):
        db.delete_user_expired_sessions(session.user_id)
        g.clear_session_cookie = True
        return
    user = db.get_user(session.user_id)
    if not user:
        db.delete_user_expired_sessions(session.user_id)
        g.clear_session_cookie = True
        return
    g.user = auth.SessionUser(session_id, session.user_id, *user)

@app.after_request
def clear_session_cookie(response: Response):
    if g.clear_session_cookie:
        response.delete_cookie("session_id")
    return response

@app.errorhandler(Exception)
def handle_errors(e):
    code = getattr(e, 'code', None)
    if not code:
        if app.debug:
            raise e # re-raise for flask default debugger
        app.logger.exception(e)        
        lg.log(lg.Event.SERVER_INTERNAL_ERROR, level=lg.Level.ERROR, extra={"error": str(e)})
    code = code or 500
    return render_template(
        "error.html", 
        code=code,
        title=ERROR_PAGE_TITLES.get(code, "Error"), 
        contact=CONTACT_EMAIL, 
        message=str(e) if app.debug else None
    ), code

# --- route handlers
@app.route("/")
def root():
    return render_template("index.html")

@app.route("/repos/<string:repo_id>", defaults={"sub": ""}, strict_slashes=False)
@app.route("/repos/<string:repo_id>/<path:sub>")
def repos(repo_id: str, sub: str):
    if len(repo_id) != 22 or not repo_id.isascii(): abort(404)
    repo = db.get_repo_select(repo_id)
    if not repo or repo.hidden: abort(404)
    if db.is_repo_owner_banned(repo_id): abort(404)
    repo_path = REPO_PATH / repo_id
    if not repo_path.is_dir(): abort(404)
    subpath = Path(sub)
    try: path = git.get_repo_path(repo_path, subpath)
    except Exception: abort(404)
    # Create response
    respone =  Response(render_template(
        "repos.html", 
        repo_id=repo_id,
        repo_name=repo.name,
        parent_chain=utils.build_parentchain(path, repo_path),
        section=utils.build_section(path)
    ))
    # Handles repos views
    day = int(time.time() // 86400)
    rv_key = f"rv_{repo_id}_{day}"
    viewed = request.cookies.get(rv_key)
    if not viewed and (not g.user or g.user.user_id != db.get_repo_user_id(repo_id)):
        ip = request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()
        if g.user: vhash = utils.viewer_hash(day, user_id=g.user.user_id)
        else: vhash = utils.viewer_hash(day, ip=ip, ua=request.user_agent.string)
        client = utils.detect_client(request.user_agent.string)
        location = utils.detect_location(ip)
        added = db.add_repo_view(repo_id, vhash, client, location)
        if added: lg.log(lg.Event.REPO_VIEW_ADDED, repo_id=repo_id)
        max_age = 86400 - int(time.time()) % 86400 # (until the end of day)
        # Save cookie to prevent mutliple rechecking 
        respone.set_cookie(rv_key, "1", max_age=max_age, secure=True, samesite="Lax") 
    return respone

@app.route("/raw/<string:repo_id>", defaults={"sub": ""}, strict_slashes=False)
@app.route("/raw/<string:repo_id>/<path:sub>")
def raw(repo_id: str, sub: str):
    if len(repo_id) != 22 or not repo_id.isascii(): abort(404)
    repo = db.get_repo_select(repo_id)
    if not repo or repo.hidden: abort(404)
    if db.is_repo_owner_banned(repo_id): abort(404)
    repo_path = REPO_PATH / repo_id
    if not repo_path.is_dir(): abort(404)
    subpath = Path(sub)
    try: path = git.get_repo_path(repo_path, subpath)
    except Exception: abort(404)
    if path.is_dir():
        if sub: return redirect(f"/repos/{repo_id}/{sub}", 303)
        # Downloading repo archive
        with NamedTemporaryFile(suffix=".zip", delete=True) as tmp:
            zip_path = Path(tmp.name)
            git.zip_repo(path, zip_path)
            return send_file(
                zip_path,
                mimetype="application/zip",
                download_name=f"{repo.name}.zip",
                as_attachment=True,
            )
        archive_path = repo_path / git.ARTIFACT_NAME
        if not archive_path.exists(): abort(404)
        return send_file(archive_path, mimetype="application/x-tar", as_attachment=True)
    return send_file(path, mimetype="text/plain", as_attachment=False)

@app.route("/repos/add", methods=["GET", "POST"])
@auth.login_required()
@auth.not_banned_required()
@auth.verification_required()
def repos_add():
    limits = db.get_user_limits(g.user.user_id)
    if not limits: abort(404, "Could not find user data")
    user_repos = db.count_user_repos(g.user.user_id)
    user_builds = db.count_user_builds(g.user.user_id)
    if user_repos >= limits.repo_limit:
        return render_template("repos_add.html", error_msg=f"Reached repo limit per user ({user_repos}/{limits.repo_limit})", is_blocked=True)
    if user_builds >= limits.build_limit:
        return render_template("repos_add.html", error_msg=f"Reached build limit per user ({user_builds}/{limits.build_limit})", is_blocked=True)
    if request.method == "GET":
        return render_template("repos_add.html")
    # POST:
    url = request.form.get("url", "").strip()
    ssh_key =  request.form.get("ssh_key")
    if not url: 
        return render_template("repos_add.html", error_msg="Missing url", url=url)
    if not utils.is_valid_repo_url(url):
        return render_template("repos_add.html", error_msg="Invalid url", url=url)
    if db.is_repo_url_for_user(url, g.user.user_id):  
        return render_template("repos_add.html", error_msg="Repo with that url already exists for that user", url=url)
    if ssh_key:
        if url.startswith("https://"): # uses HTTPS
            return render_template("repos_add.html", error_msg="To use ssh-key you need to provide ssh url", url=url)
        ssh_key = git.normalize_ssh_key(ssh_key)
        key_err = git.validate_ssh_key(ssh_key)
        if key_err:
            return render_template("repos_add.html", error_msg=key_err, url=url)
        ssh_key = git.encrypt_ssh_key(ssh_key)
    elif url.startswith("git@github.com"): # uses SSH
        return render_template("repos_add.html", error_msg="To use ssh url you need to provide ssh-key", url=url)
    else: ssh_key = None
    repo_name = url.removesuffix(".git").rsplit("/",1)[-1]
    repo_id = db.add_repo(g.user.user_id, url, repo_name, ssh_key)
    lg.log(lg.Event.REPO_ADDED, repo_id=repo_id, user_id=g.user.user_id)
    build_id = db.add_build(g.user.user_id, repo_id) # adds pending build for build worker
    lg.log(lg.Event.BUILD_QUEUED, build_id=build_id, repo_id=repo_id, user_id=g.user.user_id)
    return redirect(f"/repos/details/{repo_id}")

@app.route("/login", methods=["GET", "POST"])
def login():
    next_url = request.args.get("next")
    if g.user:
        return redirect(auth.safe_redirect_url(next_url))
    if request.method == "GET":
        return render_template("login.html", next_url=next_url)
    # POST:
    send_login = request.form.get("login", "").strip()
    send_password = request.form.get("password", "").strip()
    if not send_login or not send_password: 
        return render_template("login.html", error_msg="Missing login or password", login=send_login, next_url=next_url)
    user = db.get_user_password(send_login)
    if not user: 
        lg.log(lg.Event.AUTH_LOGIN_FAILURE, lg.Level.WARN, lg.Code.USER_NOT_FOUND, extra={"login": send_login})
        return render_template("login.html", error_msg="Invalid login or password", login=send_login, next_url=next_url)
    if not auth.check_password(send_password, user.password): 
        lg.log(lg.Event.AUTH_LOGIN_FAILURE, lg.Level.WARN, lg.Code.INVALID_PASSWORD, user_id=user.id)
        return render_template("login.html", error_msg="Invalid login or password", login=send_login, next_url=next_url)
    db.update_last_user_login(user.id)
    expires = auth.get_session_expiriation(user.role)
    session_id = db.add_session(user.id, expires)
    response = redirect(auth.safe_redirect_url(next_url))
    response.set_cookie("session_id", session_id, expires=expires, path='/', samesite='strict', httponly=True, secure=True)
    lg.log(lg.Event.AUTH_LOGIN_SUCCESS, user_id=user.id)
    return response

@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect("/dashboard")
    if request.method == "GET":
        return render_template("register.html")
    # POST:
    user_login = request.form.get("login", "").strip()
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")
    r_password = request.form.get("r_password", "")
    if not user_login or not email or not password or not r_password:
        return render_template("register.html", error_msg="Missing fields", login=user_login, email=email)
    if not utils.is_valid_email(email):
        return render_template("register.html", error_msg="Invalid email", login=user_login, email=email)
    if password != r_password:
        return render_template("register.html", error_msg="Password does not match repeated password", login=user_login, email=email)
    pass_err = utils.is_valid_password(password)
    if pass_err: 
        return render_template("register.html", error_msg=pass_err, login=user_login, email=email)
    if db.is_user_login(user_login):
        return render_template("register.html", error_msg="This login is already registered", login=user_login, email=email)
    if db.is_user_email(email):
        return render_template("register.html", error_msg="This email is already registered", login=user_login, email=email)
    hashed_password = auth.hash_password(password)
    user_id = db.add_user(user_login, email, hashed_password, 'u')
    expires = auth.get_session_expiriation('u')
    session_id = db.add_session(user_id, expires)
    response = redirect("/dashboard")
    response.set_cookie("session_id", session_id, expires=expires, path='/', samesite='strict', httponly=True, secure=True)
    lg.log(lg.Event.AUTH_REGISTER, user_id=user_id)
    # Verification email
    token = db.add_token(user_id, 'e_ver')
    emails.send_email(
        emails.EmailIntent.EMAIL_VERIFICATION,
        to=email,
        user_id=user_id,
        is_verified=False,
        user=user_login,
        token=token.id,
        expires=utils.timestamp_to_str(token.expires),
    )
    return response

@app.route("/logout")
@auth.login_required()
def logout():
    db.delete_session(g.user.session_id)
    db.delete_user_expired_sessions(g.user.user_id)
    response = redirect("/login")
    response.delete_cookie("session_id")
    lg.log(lg.Event.AUTH_LOGOUT, user_id=g.user.user_id)
    return response

@app.route("/dashboard")
@auth.login_required()
@auth.not_banned_required()
def dashboard():
    repos = db.list_user_repos(g.user.user_id)
    return render_template("dashboard.html", repos=repos)

@app.route("/views")
@auth.login_required()
@auth.not_banned_required()
@auth.verification_required()
def views():
    page = request.args.get('page', '0')
    if not page.isnumeric() or int(page) < 0: page = 0
    else: page = int(page)
    uviews = db.list_user_repo_views(g.user.user_id, offset=(page*10))
    cviews = db.count_user_repo_views(g.user.user_id)
    return render_template(
        "views.html",
        page=page,
        is_last=(len(uviews) < 10),
        views=utils.views_to_readable(uviews),
        cviews=cviews
    )

@app.route("/repos/details/<string:repo_id>")
@auth.login_required()
@auth.not_banned_required()
@auth.verification_required()
def repos_details(repo_id: str):
    if len(repo_id) != 22 or not repo_id.isascii(): abort(404)
    repo = db.get_repo(repo_id)
    if not repo: abort(404)
    if repo.user_id != g.user.user_id: abort(404)
    build = db.get_latest_build(repo_id)
    if request.args.get("status") == "true":
        return Response(utils.code_to_status(build.status) if build else "?", 200)
    limits = db.get_user_limits(repo.user_id)
    if not limits: abort(404, "Could not find user data")
    build_count = db.count_user_builds(g.user.user_id)
    visits = db.count_repo_visits(repo_id)
    return render_template(
        "repos_details.html",
        repo_id=repo_id,
        repo_name=repo.repo_name,
        url=repo.url,
        hidden=repo.hidden,
        created=utils.timestamp_to_str(repo.created),
        build_status=("?" if not build else utils.code_to_status(build.status)),
        build_timestamp=("?" if not build else utils.timestamp_to_str(build.timestamp)),
        build_size=("?" if not build else utils.size_to_str(build.size)),
        build_code=(lg.USER_MESSAGES.get(build.code, "") if build and build.code else None),
        build_count=build_count,
        build_limit=limits.build_limit,
        visits=visits
    )

@app.route("/repos/build/<string:repo_id>", methods=["POST"])
@auth.login_required()
@auth.not_banned_required()
@auth.verification_required()
def build(repo_id: str):
    if len(repo_id) != 22 or not repo_id.isascii(): abort(404)
    repo = db.get_repo_for_clone(repo_id)
    if not repo: abort(404)
    if repo.user_id != g.user.user_id: abort(404)
    limits = db.get_user_limits(g.user.user_id)
    if not limits: abort(404, "Could not find user data")
    user_builds = db.count_user_builds(g.user.user_id)
    if user_builds >= limits.build_limit:  
        abort(400, f"Reached build limit per user ({user_builds}/{limits.build_limit})")
    if db.has_repo_active_build(repo_id):  
        abort(400, "This repo already has pending build")
    build_id = db.add_build(g.user.user_id, repo_id) # adds pending build for build worker
    lg.log(lg.Event.BUILD_QUEUED, build_id=build_id, repo_id=repo_id, user_id=g.user.user_id)
    return redirect(f"/repos/details/{repo_id}")

@app.route("/repos/remove/<string:repo_id>", methods=["POST"])
@auth.login_required()
@auth.not_banned_required()
@auth.verification_required()
def repos_remove(repo_id: str):
    if len(repo_id) != 22 or not repo_id.isascii(): abort(404)
    user_id = db.get_repo_user_id(repo_id)
    if not user_id or user_id != g.user.user_id: abort(404)
    db.delete_repo(repo_id)
    path = REPO_PATH / repo_id
    if path.exists(): git.remove_protected_dir(path)
    lg.log(lg.Event.REPO_REMOVED, repo_id=repo_id, user_id=g.user.user_id)
    return redirect("/dashboard")

@app.route("/user")
@auth.login_required()
@auth.not_banned_required()
def user():
    limits = db.get_user_limits(g.user.user_id)
    if not limits: abort(404, "Could not find user data")
    email = db.get_user_email(g.user.user_id)
    build_count = db.count_user_builds(g.user.user_id)
    repo_count = db.count_user_repos(g.user.user_id)
    return render_template(
        "user.html",
        role=utils.code_to_role(g.user.role), 
        email=email,
        build_count=build_count,
        repo_count=repo_count,
        repo_limit=limits.repo_limit,
        build_limit=limits.build_limit
    )

@app.route("/user/remove", methods=["GET", "POST"])
@auth.login_required()
@auth.not_banned_required()
def user_remove():
    if request.method == "GET":
        return render_template("user_remove.html", user_login=g.user.login)
    if g.user.login == "root":
        abort(400, "Cannot remove root user")
    send_password = request.form.get("password")
    if not send_password: abort(404, "Password is required for that action")
    user = db.get_user_password(g.user.login)
    assert user is not None
    if not auth.check_password(send_password, user.password):  
        abort(404, "Incorrect password")
    repos = db.list_user_repos(g.user.user_id)
    for repo in repos:
        git.remove_protected_dir(REPO_PATH / repo.id)
    db.delete_user(g.user.user_id)
    lg.log(lg.Event.AUTH_USER_REMOVED, user_id=g.user.user_id)
    return redirect("/login")

@app.route("/admin")
@auth.login_required()
@auth.verification_required()
@auth.role_required('a')
def admin():
    repo_count = db.count_repos()
    user_count = db.count_users()
    build_24h_count = db.count_last24h_builds()
    build_7d_count = db.count_last7d_builds()
    sizes = db.sum_build_sizes()
    extracted_size = git.get_extracted_size()
    builds = db.list_builds()
    cleanup_data = cworker.get_last_cleanup()
    return render_template(
        "admin.html",
        repo_count=repo_count,
        user_count=user_count,
        build_24h_count=build_24h_count,
        build_7d_count=build_7d_count,
        build_sum_size=utils.size_to_str(sizes.size),
        build_sum_archive_size=utils.size_to_str(sizes.archive_size),
        extracted_size=utils.size_to_str(extracted_size),
        total_computed_size=utils.size_to_str(extracted_size+sizes.archive_size),
        latest_activity=utils.builds_activity_to_readable(builds),
        cleanup_data=cleanup_data
    )

@app.route("/admin/cleanup", methods=["POST"])
@auth.login_required()
@auth.verification_required()
@auth.role_required('a')
def admin_cleanup():
    lg.log(lg.Event.ADMIN_FORCED_CLEANUP, user_id=g.user.user_id)
    cworker.main()
    return redirect("/admin")

@app.route("/admin/repos")
@auth.login_required()
@auth.verification_required()
@auth.role_required('a')
def admin_repos():
    page = request.args.get('page', '0')
    if not page.isnumeric() or int(page) < 0: page = 0
    else: page = int(page)
    status = request.args.get('status', '')
    if not utils.is_vaild_status(status): status = ''
    key = request.args.get('key', '')
    if not key in ['1', '0', '']: key = ''
    hidden = request.args.get('hidden', '')
    if not hidden in ['1', '0', '']: hidden = ''
    user = request.args.get('user', '')
    repo = request.args.get('repo', '')
    url = request.args.get('url', '')
    # ---
    repos = db.list_repos(offset=(page*10), status=status, user=user, repo=repo, url=url, key=key, hidden=hidden)
    return render_template(
        "admin_repos.html",
        repos=utils.repos_activity_to_readable(repos),
        is_last=(len(repos) < 10),
        page=page,
        repo=repo,
        status=status,
        user=user,
        url=url,
        key=key,
        hidden=hidden
    )

@app.route("/admin/builds")
@auth.login_required()
@auth.verification_required()
@auth.role_required('a')
def admin_builds():
    page = request.args.get('page', '0')
    if not page.isnumeric() or int(page) < 0: page = 0
    else: page = int(page)
    status = request.args.get('status', '')
    if not utils.is_vaild_status(status): status = ''
    user = request.args.get('user', '')
    repo_id = request.args.get('repo', '')
    code = request.args.get('code')
    # ---
    builds = db.list_builds(offset=(page*10), status=status, user=user, repo_id=repo_id, code=code)
    return render_template(
        "admin_builds.html",
        builds=utils.builds_activity_to_readable(builds),
        is_last=(len(builds) < 10),
        page=page,
        status=status,
        user=user,
        repo=repo_id,
        code=code
    )

@app.route("/admin/users")
@auth.login_required()
@auth.verification_required()
@auth.role_required('a')
def admin_users():
    page = request.args.get('page', '0')
    if not page.isnumeric() or int(page) < 0: page = 0
    else: page = int(page)
    verified = request.args.get('verified', '')
    if not verified in ['1', '0', '']: verified = ''
    banned = request.args.get('banned', '')
    if not banned in ['1', '0', '']: banned = ''
    role = request.args.get('role', '')
    if not role in ['a', 'u', '']: role = ''
    inactive = request.args.get('inactive', '')
    if not inactive in ['1', '0', '']: inactive = ''
    user_login = request.args.get('login', '')
    email = request.args.get('email', '')
    # ---
    users = db.list_users(
        offset=(page*10), 
        login=user_login, 
        email=email, 
        is_verified=verified, 
        is_banned=banned, 
        role=role,
        inactive=inactive
    )
    return render_template(
        "admin_users.html",
        users=utils.users_activity_to_readable(users),
        is_last=(len(users) < 10),
        page=page,
        login=user_login,
        email=email,
        verified=verified,
        banned=banned,
        role=role,
        inactive=inactive
    )

@app.route("/admin/users/<int:user_id>", methods=["GET", "POST"])
@auth.login_required()
@auth.verification_required()
@auth.role_required('a')
def admin_users_id(user_id: int):
    user = db.get_user(user_id)
    if not user: abort(404)
    # methods:
    if request.method == "GET":
        limits = db.get_user_limits(user_id)
        if not limits: abort(404, "Could not find user data")
        email = db.get_user_email(user_id)
        user_ts = db.get_user_ts(user_id)
        assert user_ts
        build_count = db.count_user_builds(user_id)
        repos = db.list_user_repos(user_id)
        banned_by = None
        ban_reason = None
        banned_at = None
        if user.is_banned: 
            ban = db.get_user_ban(user_id) 
            if ban:
                banned_by = ban.banned_by
                banned_at = utils.timestamp_to_str(ban.banned_at)
                ban_reason = ban.ban_reason
        return render_template(
            "admin_users_id.html", 
            user_id=user_id,
            user_login=user.login,
            is_verified=user.is_verified,
            inactive=user.inactive,
            is_banned=user.is_banned,
            role=utils.code_to_role(user.role),
            email=email,
            build_count=build_count,
            repo_count=len(repos),
            repo_limit=limits.repo_limit,
            build_limit=limits.build_limit,
            repos=repos,
            banned_by=banned_by,
            banned_at=banned_at,
            ban_reason=ban_reason,
            created=utils.timestamp_to_str(user_ts.created),
            last_login=utils.timestamp_to_str(user_ts.last_login)
        )
    # method == POST
    # Set verified
    set_verified = request.form.get("set_verified", "")
    if set_verified:
        if user.login == "root": abort(400, "Cannot modify root user")
        if set_verified not in ["true", "false"]: abort(400, "Invalid `set_verified`")
        if user.role == 'a': abort(400, "Cannot unverify admin user")
        set_verified = set_verified == "true"
        db.set_user_verified(user_id, set_verified)
        lg.log(
            lg.Event.ADMIN_USER_VERIFICATION_CHANGE, 
            lg.Level.WARN, user_id=user_id, 
            extra={"admin_id": g.user.user_id, "value": set_verified}
        )
    # Set role
    set_role = request.form.get("set_role", "")
    if set_role:
        if user.login == "root": abort(400, "Cannot modify root user")
        if set_role not in ["a", "u"]: abort(400, "Invalid `set_role`")
        if not user.is_verified: abort(400, "Cannot promote unverified user")
        if user.is_banned: abort(400, "Cannot promote banned user")
        db.set_user_role(user_id, set_role) # type: ignore -- type checked previously
        lg.log(
            lg.Event.ADMIN_USER_ROLE_CHANGE, 
            lg.Level.WARN, user_id=user_id, 
            extra={"admin_id": g.user.user_id, "value": set_role}
        )
    # Set banned
    set_banned = request.form.get("set_banned", "")
    if set_banned:
        if user.role == 'a': abort(400, "Cannot set banned for admin users")
        if set_banned not in ["true", "false"]: abort(400, "Invalid `set_banned`")
        if set_banned == "true":
            if user.is_banned: abort(400, "User already banned")
            ban_reason = request.form.get("ban_reason")
            db.ban_user(user_id, g.user.user_id, ban_reason)
            db.fail_all_user_pending_builds(user_id)
            lg.log(
                lg.Event.ADMIN_USER_BAN,
                lg.Level.WARN, user_id=user_id,
                extra={"admin_id": g.user.user_id, "reason": ban_reason}
            )
            if user.is_verified:
                email = db.get_user_email(user_id)
                assert email
                emails.send_email(
                    emails.EmailIntent.ACCOUNT_BANNED,
                    to=email,
                    user_id=user_id,
                    is_verified=user.is_verified,
                    user=user.login,
                    reason=ban_reason 
                )
        else:
            if not user.is_banned: abort(400, "User is not banned")
            db.unban_user(user_id)
            lg.log(
                lg.Event.ADMIN_USER_UNBAN,
                lg.Level.WARN, user_id=user_id,
                extra={"admin_id": g.user.user_id}
            )
            if user.is_verified:
                email = db.get_user_email(user_id)
                assert email
                emails.send_email(
                    emails.EmailIntent.ACCOUNT_UNBANNED,
                    to=email,
                    user_id=user_id,
                    is_verified=user.is_verified,
                    user=user.login,
                )
    # Expire
    expire = request.form.get("expire", "")
    if expire == "true":
        db.expire_user_builds(user_id)
        lg.log(
            lg.Event.ADMIN_USER_QUOTA_RESET, 
            lg.Level.WARN, user_id=user_id, 
            extra={"admin_id": g.user.user_id}
        )
    return redirect(f'/admin/users/{user_id}')

@app.route("/verify")
@auth.login_required()
@auth.not_banned_required()
def verify():
    if g.user.login == "root": abort(400, "Cannot modify root user")
    email = db.get_user_email(g.user.user_id)
    assert email is not None
    token = request.args.get("t")
    blocked = db.has_recent_token(g.user.user_id, 'e_ver')
    if g.user.is_verified or not token: return render_template("verify.html", email=email, blocked=blocked, is_verified=g.user.is_verified)
    is_valid = db.is_valid_token(token, g.user.user_id, 'e_ver')
    if not is_valid: 
        lg.log(lg.Event.AUTH_EMAIL_VERIFY_INVALID, lg.Level.WARN, user_id=g.user.user_id)
        return render_template("verify.html", email=email, blocked=blocked, is_verified=g.user.is_verified)
    db.delete_user_tokens(g.user.user_id, 'e_ver')
    db.set_user_verified(g.user.user_id, True)
    lg.log(lg.Event.AUTH_EMAIL_VERIFY_COMPLETE, user_id=g.user.user_id)
    return render_template("verify.html", is_verified=True)

@app.route("/verify/resend", methods=["POST"])
@auth.not_banned_required()
@auth.login_required()
def verify_resend():
    if g.user.is_verified: return redirect("/dashboard")
    email = db.get_user_email(g.user.user_id)
    assert email is not None
    if db.has_recent_token(g.user.user_id, 'e_ver'):
        lg.log(lg.Event.AUTH_EMAIL_VERIFY_REQUEST_BLOCKED, lg.Level.WARN, user_id=g.user.user_id)
        return render_template("verify.html", error_msg="Rate limit exceeded", email=email, blocked=True, is_verified=g.user.is_verified)
    token = db.add_token(g.user.user_id, 'e_ver')
    emails.send_email(
        emails.EmailIntent.EMAIL_VERIFICATION,
        to=email,
        user_id=g.user.user_id,
        is_verified=g.user.is_verified,
        user=g.user.login,
        token=token.id,
        expires=utils.timestamp_to_str(token.expires),
    )
    lg.log(lg.Event.AUTH_EMAIL_VERIFY_REQUEST, user_id=g.user.user_id)
    return render_template("verify.html", email=email, blocked=True, is_verified=g.user.is_verified)

@app.route("/password/change", methods=["GET", "POST"])
@auth.login_required()
@auth.not_banned_required()
@auth.verification_required()
def password_change():
    if g.user.login == "root": abort(400, "Cannot modify root user")
    if request.method == "GET":
        return render_template("password_change.html")
    c_pass = request.form.get("c_password")
    n_pass = request.form.get("n_password")
    r_pass = request.form.get("r_password")
    if not c_pass or not n_pass or not r_pass: 
        return render_template("password_change.html", error_msg="Missing data")
    if n_pass != r_pass:
        return render_template("password_change.html", error_msg="Password does not match repeated password")
    if c_pass == n_pass:
        return render_template("password_change.html", error_msg="New password cannot be the same as previous password")
    pass_err = utils.is_valid_password(n_pass)
    if pass_err:
        return render_template("password_change.html", error_msg=pass_err)
    user = db.get_user_password(g.user.login)
    assert user is not None
    if not auth.check_password(c_pass, user.password):
        lg.log(lg.Event.AUTH_PASSWORD_CHANGE_FAILURE,  lg.Level.WARN, user_id=user.id)
        return render_template("password_change.html", error_msg="Invalid password")
    upd_pass = auth.hash_password(n_pass)
    db.set_user_password(user.id, upd_pass)
    db.delete_user_sessions(user.id)
    g.clear_session_cookie = True
    lg.log(lg.Event.AUTH_PASSWORD_CHANGE_SUCCESS, user_id=user.id)
    return redirect("/login")

@app.route("/password/recover", methods=["GET", "POST"])
def password_recover():
    if request.method == "GET":
        return render_template("password_recover.html")
    email = request.form.get("email", "")
    user = db.get_user_by_email(email)
    if not user: 
        lg.log(lg.Event.AUTH_PASSWORD_RECOVERY_REQUEST_INVALID, lg.Level.DEBUG)
        return render_template("password_recover.html", resp=True)
    if not user.is_verified:
        lg.log(lg.Event.AUTH_PASSWORD_RECOVERY_REQUEST_BLOCKED, lg.Level.WARN, user_id=user.id, extra={"msg": "Not verified"})
        return render_template("password_recover.html", resp=True)
    if db.has_recent_token(user.id, 'p_rec'):
        lg.log(lg.Event.AUTH_PASSWORD_RECOVERY_REQUEST_BLOCKED, lg.Level.WARN, user_id=user.id, extra={"msg": "Rate limit"})
        return render_template("password_recover.html", resp=True)
    token = db.add_token(user.id, 'p_rec')
    emails.send_email(
        emails.EmailIntent.PASSWORD_RECOVERY,
        to=email,
        user_id=user.id,
        is_verified=user.is_verified,
        user=user.login,
        token=token.id,
        expires=utils.timestamp_to_str(token.expires),
    )
    lg.log(lg.Event.AUTH_PASSWORD_RECOVERY_REQUEST, user_id=user.id)
    return render_template("password_recover.html", resp=True)

@app.route("/password/reset", methods=["GET", "POST"])
def password_reset():
    token = request.args.get("t")
    if not token: 
        lg.log(lg.Event.AUTH_PASSWORD_RESET_INVALID, lg.Level.WARN)
        abort(404)
    uid = db.get_valid_token_user(token, 'p_rec')
    if not uid: 
        lg.log(lg.Event.AUTH_PASSWORD_RESET_INVALID, lg.Level.WARN)    
        abort(404)
    if not db.is_user_verified(uid):
        lg.log(lg.Event.AUTH_PASSWORD_RESET_INVALID, lg.Level.WARN)    
        abort(404)        
    user_login = db.get_user_login(uid)
    if request.method == "GET":
        return render_template("password_reset.html", token=token, login=user_login)
    # POST
    password = request.form.get("password")
    r_password = request.form.get("r_password")
    if not password or not r_password: 
        return render_template("password_reset.html", token=token, login=user_login, error_msg="Missing data")
    if password != r_password:
        return render_template("password_reset.html", token=token, login=user_login, error_msg="Password does not match repeated password")
    pass_err = utils.is_valid_password(password)
    if pass_err:
        return render_template("password_reset.html", token=token, login=user_login, error_msg=pass_err)
    upd_pass = auth.hash_password(password)
    db.set_user_password(uid, upd_pass)
    db.delete_user_sessions(uid)
    db.delete_user_tokens(uid, 'p_rec')
    lg.log(lg.Event.AUTH_PASSWORD_RESET_SUCCESS, user_id=uid)    
    return redirect("/login")

@auth.login_required()
@app.route("/banned")
def banned():
    ban = db.get_user_ban(g.user.user_id)
    if not ban: return redirect("/dashboard")
    return render_template(
        "banned.html",
        ban_reason=ban.ban_reason,
        banned_at=utils.timestamp_to_str(ban.banned_at),
        contact=CONTACT_EMAIL
    )