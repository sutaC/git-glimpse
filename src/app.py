from flask import Flask, Response, render_template, abort, redirect, send_file, request, g
from globals import REPO_PATH, DATABASE_PATH
from tempfile import NamedTemporaryFile
from lib.database import Database
from dotenv import load_dotenv
from pathlib import Path
import lib.utils as utils
import lib.logger as lg
import lib.auth as auth
import lib.git as git
import time
import os

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")

db = Database(DATABASE_PATH)
with app.app_context():
    db.init_db()

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
    user_login, role, is_verified = user
    g.user = auth.User(session_id, session.user_id, user_login, role, is_verified)

@app.after_request
def clear_session_cookie(response: Response):
    if g.clear_session_cookie:
        response.delete_cookie("session_id")
    return response

@app.route("/")
def root():
    return render_template("index.html")

@app.route("/repos/<string:repo_id>", defaults={"sub": ""}, strict_slashes=False)
@app.route("/repos/<string:repo_id>/<path:sub>")
def repos(repo_id: str, sub: str):
    if len(repo_id) != 22 or not repo_id.isascii(): abort(404)
    repo_name = db.get_repo_name(repo_id)
    if not repo_name: abort(404)
    repo_path = REPO_PATH / repo_id
    if not repo_path.is_dir():
        abort(404, "Repo not found on server")
    subpath = Path(sub)
    try: path = git.get_repo_path(repo_path, subpath)
    except git.RepoError as e: abort(400, lg.USER_MESSAGES.get(e.code, ""))
    # Makes list of path urls to all parent dirs
    rel_parts = path.relative_to(REPO_PATH / repo_id / "extracted").parts[:-1]  # exclude file itself
    parentchain = ['/'.join(rel_parts[:i+1]) for i in range(len(rel_parts))]
    return render_template(
        "repos.html", 
        repo_name=repo_name,
        path_str=str(subpath).lstrip("."),
        path=path,
        repo_id=repo_id,
        parent_chain=parentchain,
        is_text=utils.is_text(path)
    )

@app.route("/raw/<string:repo_id>", defaults={"sub": ""}, strict_slashes=False)
@app.route("/raw/<string:repo_id>/<path:sub>")
def raw(repo_id: str, sub: str):
    if len(repo_id) != 22 or not repo_id.isascii(): abort(404)
    repo_name = db.get_repo_name(repo_id)
    if not repo_name: abort(404)
    repo_path = REPO_PATH / repo_id
    if not repo_path.is_dir():
        abort(404, "Repo not found on server")
    subpath = Path(sub)
    try: path = git.get_repo_path(repo_path, subpath)
    except git.RepoError as e: abort(400, lg.USER_MESSAGES.get(e.code, ""))
    if path.is_dir():
        if sub: return redirect(f"/repos/{repo_id}/{sub}", 303)
        # Downloading repo archive
        with NamedTemporaryFile(suffix=".zip", delete=True) as tmp:
            zip_path = Path(tmp.name)
            git.zip_repo(path, zip_path)
            return send_file(
                zip_path,
                mimetype="application/zip",
                download_name=f"{repo_name}.zip",
                as_attachment=True,
            )
        archive_path = repo_path / "build.tar.zst"
        if not archive_path.exists(): abort(404)
        return send_file(archive_path, mimetype="application/x-tar", as_attachment=True)
    return send_file(path, mimetype="text/plain", as_attachment=False)

@app.route("/repos/add", methods=["GET", "POST"])
@auth.login_required()
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
    # TODO: block if not verified
    url = request.form.get("url", "").strip()
    if not url: 
        return render_template("repos_add.html", error_msg="Missing url", url=url)
    ssh_key =  request.form.get("ssh_key")
    if ssh_key: ssh_key = ssh_key.strip()
    else: ssh_key = None
    if not utils.is_valid_repo_url(url):
        return render_template("repos_add.html", error_msg="Invalid url", url=url)
    if db.is_repo_url_for_user(url, g.user.user_id):  
        return render_template("repos_add.html", error_msg="Repo with that url already exists for that user", url=url)
    if url.startswith("https://") and ssh_key:
        return render_template("repos_add.html", error_msg="To use ssh-key you need to provide ssh url", url=url)
    if ssh_key: ssh_key = git.encrypt_ssh_key(ssh_key)
    repo_name = url.removesuffix(".git").rsplit("/",1)[-1]
    repo_id = db.add_repo(g.user.user_id, url, repo_name, ssh_key)
    lg.log(lg.Event.REPO_ADDED, repo_id=repo_id, user_id=g.user.user_id)
    build_id = db.add_build(g.user.user_id, repo_id) # adds pending build for build worker
    lg.log(lg.Event.BUILD_QUEUED, build_id=build_id, repo_id=repo_id, user_id=g.user.user_id)
    return redirect(f"/repos/details/{repo_id}")

@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect("/dashboard")
    if request.method == "GET":
        return render_template("login.html")
    # POST:
    send_login = request.form.get("login", "").strip()
    send_password = request.form.get("password", "").strip()
    if not send_login or not send_password: 
        return render_template("login.html", error_msg="Missing login or password", login=send_login)
    user = db.get_user_password(send_login)
        
    if not user: 
        lg.log(lg.Event.AUTH_LOGIN_FAILURE, lg.Level.WARN, lg.Code.USER_NOT_FOUND, extra={"login": send_login})
        return render_template("login.html", error_msg="Invalid login or password", login=send_login)
    if not auth.check_password(send_password, user.password): 
        lg.log(lg.Event.AUTH_LOGIN_FAILURE, lg.Level.WARN, lg.Code.INVALID_PASSWORD, user_id=user.id)
        return render_template("login.html", error_msg="Invalid login or password", login=send_login)
    expires = auth.get_session_expiriation(user.role)
    session_id = db.add_session(user.id, expires)
    response = redirect("/dashboard")
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
    if utils.is_valid_email(email):
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
    # TODO: send verification email
    hashed_password = auth.hash_password(password)
    user_id = db.add_user(user_login, email, hashed_password, 'u')
    expires = auth.get_session_expiriation('u')
    session_id = db.add_session(user_id, expires)
    response = redirect("/dashboard")
    response.set_cookie("session_id", session_id, expires=expires, path='/', samesite='strict', httponly=True, secure=True)
    lg.log(lg.Event.AUTH_REGISTER, user_id=user_id)
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
def dashboard():
    # TODO: verification message if not verified
    repos = db.list_user_repos(g.user.user_id)
    return render_template(
        "dashboard.html", 
        repos=repos,
        is_admin=(g.user.role == 'a')
    )

@app.route("/repos/details/<string:repo_id>")
@auth.login_required()
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
    return render_template(
        "repos_details.html",
        user_login=g.user.login,
        repo_id=repo_id,
        repo_name=repo.repo_name,
        url=repo.url,
        created=utils.timestamp_to_str(repo.created),
        build_status=("?" if not build else utils.code_to_status(build.status)),
        build_timestamp=("?" if not build else utils.timestamp_to_str(build.timestamp)),
        build_size=("?" if not build else utils.size_to_str(build.size)),
        build_code=(lg.USER_MESSAGES.get(build.code, "") if build and build.code else None),
        build_count=build_count,
        build_limit=limits.build_limit
    )

@app.route("/repos/build/<string:repo_id>", methods=["POST"])
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

@app.route("/repos/remove/<string:repo_id>")
def repos_remove(repo_id: str):
    if len(repo_id) != 22 or not repo_id.isascii(): abort(404)
    user_id = db.get_repo_user_id(repo_id)
    if not user_id or user_id != g.user.user_id: abort(404)
    db.delete_repo(repo_id)
    path = REPO_PATH / repo_id
    try:
        if path.exists(): git.remove_protected_dir(path)
    except Exception as e:
        lg.log(lg.Event.SERVER_internal_ERROR, lg.Level.ERROR, repo_id=repo_id, extra={"reason": str(e)})
        abort(500, "Repo removal failed")
    lg.log(lg.Event.REPO_REMOVED, repo_id=repo_id, user_id=g.user.user_id)
    return redirect("/dashboard")

@app.route("/user")
@auth.login_required()
def user():
    limits = db.get_user_limits(g.user.user_id)
    if not limits: abort(404, "Could not find user data")
    email = db.get_user_email(g.user.user_id)
    build_count = db.count_user_builds(g.user.user_id)
    repo_count = db.count_user_repos(g.user.user_id)
    return render_template(
        "user.html",
        user_login=g.user.login, 
        role=utils.code_to_role(g.user.role), 
        is_verified=g.user.is_verified,
        email=email,
        build_count=build_count,
        repo_count=repo_count,
        repo_limit=limits.repo_limit,
        build_limit=limits.build_limit
    )

@app.route("/user/remove", methods=["GET", "POST"])
@auth.login_required()
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
@auth.role_required('a')
def admin():
    repo_count = db.count_repos()
    user_count = db.count_users()
    build_24h_count = db.count_last24h_builds()
    build_7d_count = db.count_last7d_builds()
    sizes = db.sum_build_sizes()
    extracted_size = git.get_extracted_size()
    builds = db.list_builds()
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
    )

@app.route("/admin/repos")
@auth.login_required()
@auth.role_required('a')
def admin_repos():
    page = request.args.get('page', '0')
    if not page.isnumeric() or int(page) < 0: page = 0
    else: page = int(page)
    status = request.args.get('status', '')
    if not utils.is_vaild_status(status): status = ''
    key = request.args.get('key', '')
    if not key in ['1', '0', '']: key = ''
    user = request.args.get('user', '')
    repo = request.args.get('repo', '')
    url = request.args.get('url', '')
    # ---
    repos = db.list_repos(offset=(page*10), status=status, user=user, repo=repo, url=url, key=key)
    return render_template(
        "admin_repos.html",
        repos=utils.repos_activity_to_readable(repos),
        is_last=(len(repos) < 10),
        page=page,
        repo=repo,
        status=status,
        user=user,
        url=url,
        key=key
    )

@app.route("/admin/builds")
@auth.login_required()
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
@auth.role_required('a')
def admin_users():
    page = request.args.get('page', '0')
    if not page.isnumeric() or int(page) < 0: page = 0
    else: page = int(page)
    verified = request.args.get('verified', '')
    if not verified in ['1', '0', '']: verified = ''
    role = request.args.get('role', '')
    if not role in ['a', 'u', '']: role = ''
    user_login = request.args.get('login', '')
    email = request.args.get('email', '')
    # ---
    users = db.list_users(offset=(page*10), login=user_login, email=email, is_verified=verified, role=role)
    return render_template(
        "admin_users.html",
        users=utils.users_activity_to_readable(users),
        is_last=(len(users) < 10),
        page=page,
        login=user_login,
        email=email,
        verified=verified,
        role=role
    )

@app.route("/admin/users/<int:user_id>", methods=["GET", "POST"])
@auth.login_required()
@auth.role_required('a')
def admin_users_id(user_id: int):
    user = db.get_user(user_id)
    if not user: abort(404)
    # methods:
    if request.method == "GET":
        limits = db.get_user_limits(user_id)
        if not limits: abort(404, "Could not find user data")
        email = db.get_user_email(user_id)
        build_count = db.count_user_builds(user_id)
        repos = db.list_user_repos(user_id)
        return render_template(
            "admin_users_id.html", 
            user_id=user_id,
            user_login=user.login,
            is_verified=user.is_verified,
            role=utils.code_to_role(user.role),
            email=email,
            build_count=build_count,
            repo_count=len(repos),
            repo_limit=limits.repo_limit,
            build_limit=limits.build_limit,
            repos=repos
        )
    # method == POST
    # Set verified
    set_verified = request.form.get("set_verified", "")
    if set_verified:
        if user.login == "root": abort(400, "Cannot modify root user")
        if set_verified not in ["true", "false"]: abort(400, "Invalid `set_verified`")
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
        db.set_user_role(user_id, set_role) # type: ignore -- type checked previously
        lg.log(
            lg.Event.ADMIN_USER_ROLE_CHANGE, 
            lg.Level.WARN, user_id=user_id, 
            extra={"admin_id": g.user.user_id, "value": set_role}
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

@app.teardown_appcontext
def db_close(error=None):
    db._close()

# TODO: /verify : verification emails
# TODO: /verify/resend : resend verification emails
# TODO: /recover : recover password by emails
# TODO: /reset : reset password by emails
