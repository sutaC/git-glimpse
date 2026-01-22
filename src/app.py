from tempfile import NamedTemporaryFile
from flask import Flask, Response, render_template, abort, redirect, send_file, request, g
from lib.database import Database
from dotenv import load_dotenv
from pathlib import Path
import lib.utils as utils
import lib.auth as auth
import lib.git as git
import urllib.parse
import time
import os

load_dotenv()

PROJECT_ROOT_PATH = Path(__file__).parent.parent 
DATABASE_PATH = PROJECT_ROOT_PATH / "database.db"
REPO_PATH =  PROJECT_ROOT_PATH / "repo"
SECRET_KEY = os.environ.get("SECRET_KEY")

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY

REPO_PATH.mkdir(exist_ok=True)

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

@app.route("/repo/<string:repo_id>", defaults={"sub": ""}, strict_slashes=False)
@app.route("/repo/<string:repo_id>/<path:sub>")
def repo(repo_id: str, sub: str):
    if len(repo_id) != 22 or not repo_id.isascii(): abort(404)
    repo_name = db.get_repo_name(repo_id)
    if not repo_name: abort(404)
    repo_path = REPO_PATH / repo_id
    if not repo_path.is_dir():
        abort(410, "Repo is not on server")
    subpath = Path(sub)
    try: path = git.get_repo_path(repo_path, subpath)
    except git.RepoError as e: abort(e.code, e.msg)
    # Makes list of path urls to all parent dirs
    rel_parts = path.relative_to(REPO_PATH / repo_id / "extracted").parts[:-1]  # exclude file itself
    parentchain = ['/'.join(rel_parts[:i+1]) for i in range(len(rel_parts))]
    return render_template(
        "repo.html", 
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
        abort(410, "Repo is not on server")
    subpath = Path(sub)
    try: path = git.get_repo_path(repo_path, subpath)
    except git.RepoError as e: abort(e.code, e.msg)
    if path.is_dir():
        if sub: return redirect(f"/repo/{repo_id}/{sub}", 303)
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

@app.route("/repo/add", methods=["GET", "POST"])
@auth.login_required()
def repo_add():
    if request.method == "GET":
        return render_template("repo_add.html")
    # POST:
    # TODO: block if not verified
    url = request.form.get("url", "").strip()
    if not url: abort(400, "Missing url")
    ssh_key =  request.form.get("ssh_key")
    if ssh_key: ssh_key = ssh_key.strip()
    else: ssh_key = None
    if not utils.is_valid_repo_url(url):
        abort(400, "Invalid url")
    if db.is_repo_url_for_user(url, g.user.user_id):  
        abort(400, "Repo with that url already exists for that user")
    limits = db.get_user_limits(g.user.user_id)
    if not limits: abort(500, "Could not resolve user limits")
    user_repos = db.count_user_repos(g.user.user_id)
    if user_repos >= limits.repo_limit:
        abort(400, f"Reached repo limit per user ({user_repos}/{limits.repo_limit})")
    user_builds = db.count_user_builds(g.user.user_id)
    if user_builds >= limits.builds_user_limit:
        abort(400, f"Reached build limit per user ({user_builds}/{limits.builds_user_limit})")
    if url.startswith("https://") and ssh_key:
        abort(400, "To use ssh-key you need to provide ssh url")
    if ssh_key: ssh_key = git.encrypt_ssh_key(ssh_key)
    # build
    repo_name = url.removesuffix(".git").rsplit("/",1)[-1]
    repo_id = db.add_repo(g.user.user_id, url, repo_name, ssh_key)
    path = REPO_PATH / repo_id
    build_id = db.add_build(g.user.user_id, repo_id)
    repo_size = None
    archive_size = None
    try:
        repo_size, archive_size = git.clone_repo(url, path, ssh_key)
    except git.RepoError as re:
        db.update_build(build_id, re.type)
        git.remove_protected_dir(path)
        if re.type == 'f': abort(re.code, f"Build failed: {re.msg}")
        elif re.type == 'v': abort(re.code, f"Build detected violation of rules: {re.msg}")
    db.update_build(build_id, 's', repo_size, archive_size)
    return redirect(f"/repo/details/{repo_id}")

@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect("/dashboard")
    if request.method == "GET":
        return render_template("login.html")
    # POST:
    send_login = request.form.get("login", "").strip()
    send_password = request.form.get("password", "").strip()
    if not send_login or not send_password: abort(400, "Missing login or password")
    user = db.get_user_password(send_login)
    if not user: abort(400, "Invalid login or password")
    if not auth.check_password(send_password, user.password): 
        abort(400, "Invalid login or password")
    expires = auth.get_session_expiriation(user.role)
    session_id = db.add_session(user.id, expires)
    response = redirect("/dashboard")
    response.set_cookie("session_id", session_id, expires=expires, path='/', samesite='strict', httponly=True, secure=True)
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
        abort(400, "Missing data")
    if utils.is_valid_email(email):
        abort(400, "Invalid email")
    if password != r_password:
        abort(400, "Password doesn't match repeated password")
    pass_err = utils.is_valid_password(password)
    if pass_err: abort(400, pass_err)
    if db.is_user_login(user_login):
        abort(400, 'Login is already registered')
    if db.is_user_email(email):
        abort(400, 'Email is already registered')
    # TODO: send verification email
    hashed_password = auth.hash_password(password)
    user_id = db.add_user(user_login, email, hashed_password, 'u')
    expires = auth.get_session_expiriation('u')
    session_id = db.add_session(user_id, expires)
    response = redirect("/dashboard")
    response.set_cookie("session_id", session_id, expires=expires, path='/', samesite='strict', httponly=True, secure=True)
    return response

@app.route("/logout")
@auth.login_required()
def logout():
    db.delete_session(g.user.session_id)
    db.delete_user_expired_sessions(g.user.user_id)
    response = redirect("/login")
    response.delete_cookie("session_id")
    return response

@app.route("/dashboard")
@auth.login_required()
def dashboard():
    # TODO: verification message if not verified
    repos = db.list_user_repos(g.user.user_id)
    limits = db.get_user_limits(g.user.user_id)
    if not limits: abort(500, "Could not resolve user limits")
    user_build_count = db.count_user_builds(g.user.user_id)
    repo_count = db.count_user_repos(g.user.user_id)
    return render_template(
        "dashboard.html", 
        repos=repos, 
        builds_user_limit=limits.builds_user_limit,
        repo_limit=limits.repo_limit,
        user_build_count=user_build_count,
        repo_count=repo_count,
        is_admin=(g.user.role == 'a')
    )

@app.route("/repo/details/<string:repo_id>")
@auth.login_required()
def details(repo_id: str):
    if len(repo_id) != 22 or not repo_id.isascii(): abort(404)
    repo = db.get_repo(repo_id)
    if not repo: abort(404)
    if repo.user_id != g.user.user_id and g.user.role != 'a': abort(404)
    build = db.get_latest_build(repo_id)
    limits = db.get_user_limits(repo.user_id)
    if not limits: abort(500, "Could not resolve user limits")
    repo_build_count = db.count_repo_builds(repo_id)
    user_login = g.user.login if repo.user_id == g.user.user_id else db.get_user_login(repo.user_id)
    return render_template(
        "details.html",
        user_login=user_login,
        repo_id=repo_id,
        repo_name=repo.repo_name,
        url=repo.url,
        is_admin_view=(repo.user_id != g.user.user_id and g.user.role == 'a'),
        created=utils.timestamp_to_str(repo.created),
        build_status=("?" if not build else utils.code_to_status(build.status)),
        build_timestamp=("?" if not build else utils.timestamp_to_str(build.timestamp)),
        build_size=("?" if not build else utils.size_to_str(build.size)),
        builds_repo_limit=limits.builds_repo_limit,
        repo_build_count=repo_build_count
    )

@app.route("/repo/build/<string:repo_id>")
def build(repo_id: str):
    if len(repo_id) != 22 or not repo_id.isascii(): abort(404)
    repo = db.get_repo_for_clone(repo_id)
    if not repo: abort(404)
    if repo.user_id != g.user.user_id: abort(404)
    limits = db.get_user_limits(g.user.user_id)
    if not limits: abort(500, "Could not resolve user limits")
    user_builds = db.count_user_builds(g.user.user_id)
    if user_builds >= limits.builds_user_limit:  
        abort(400, f"Reached build limit per user ({user_builds}/{limits.builds_user_limit})")
    repo_builds = db.count_repo_builds(repo_id)
    if repo_builds >= limits.builds_repo_limit:   
        abort(400, f"Reached build limit per repo ({repo_builds}/{limits.builds_repo_limit})")
    if db.has_repo_pending_build(repo_id):  
        abort(400, "This repo already has pending build")
    # build
    path = REPO_PATH / repo_id
    ssh_key_plain = git.decrypt_ssh_key(repo.ssh_key) if repo.ssh_key else None
    build_id = db.add_build(g.user.user_id, repo_id)
    repo_size = None
    archive_size = None
    try:
        repo_size, archive_size = git.clone_repo(repo.url, path, ssh_key_plain)
    except git.RepoError as re:
        db.update_build(build_id, re.type)   
        git.remove_protected_dir(path)
        if re.type == 'f': abort(re.code, f"Build failed: {re.msg}")
        elif re.type == 'v': abort(re.code, f"Build detected violation of rules: {re.msg}")
    db.update_build(build_id, 's', repo_size, archive_size)
    return redirect(f"/repo/details/{repo_id}")

@app.route("/repo/remove/<string:repo_id>")
def remove(repo_id: str):
    if len(repo_id) != 22 or not repo_id.isascii(): abort(404)
    user_id = db.get_repo_user_id(repo_id)
    if not user_id or user_id != g.user.user_id: abort(404)
    db.delete_repo(repo_id)
    path = REPO_PATH / repo_id
    try:
        if path.exists(): git.remove_protected_dir(path)
    except Exception as e:
        abort(500, "Removal failed")
    return redirect("/dashboard")

@app.route("/user")
@auth.login_required()
def user():
    email = db.get_user_email(g.user.user_id)
    return render_template(
        "user.html",
        user_login=g.user.login, 
        role=utils.code_to_role(g.user.role), 
        is_verified=g.user.is_verified,
        email=email
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
    latest_activity = db.list_builds()
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
        latest_activity=[
            (acc.id, acc.repo_id, acc.user_login, utils.code_to_status(acc.status), utils.timestamp_to_str(acc.timestamp), utils.size_to_str(acc.size)) 
            for acc in latest_activity
        ]
    )

@app.route("/admin/builds")
@auth.login_required()
@auth.role_required('a')
def admin_builds():
    page = request.args.get('page', '0')
    if not page.isnumeric() or int(page) < 0: page = 0
    else: page = int(page)
    status = request.args.get('status', '')
    if not status in ['p', 's', 'v', 'f', '']: status = ''
    user = request.args.get('user', '')
    repo_id = request.args.get('repo', '')
    # ---
    builds = db.list_builds(offset=(page*10), status=status, user=user, repo_id=repo_id)
    return render_template(
        "admin_builds.html",
        builds=[
            (b.id, b.repo_id, b.user_login, utils.code_to_status(b.status), utils.timestamp_to_str(b.timestamp), utils.size_to_str(b.size))
            for b in builds
        ],
        is_last=(len(builds) < 10),
        page=page,
        status=status,
        user=user,
        repo=repo_id
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
        users=[
            (u.id, u.login, u.email, u.is_verified, utils.code_to_role(u.role), utils.timestamp_to_str(u.created))
            for u in users
        ],
        is_last=(len(users) < 10),
        page=page,
        login=user_login,
        email=email,
        verified=verified,
        role=role
    )

@app.route("/admin/users/verify", methods=["POST"])
@auth.role_required('a')
def admin_users_verify():
    user_id = request.form.get("user_id", "")
    if not user_id  or not user_id.isnumeric(): abort(400, "Missing or invalid `user_id`")
    user_id = int(user_id)
    verified = request.form.get("verified", "")
    if not verified or verified not in ["true", "false"]: abort(400, "Missing or invalid `verified`")
    verified = verified == "true"
    user_login = db.get_user_login(user_id)
    if not user_login: abort(404, "User not found")
    if user_login == "root": abort(400, "Cannot modify root user")
    db.set_user_verified(user_id, verified)
    return redirect(f'/admin/users?user={urllib.parse.quote(user_login)}')

@app.teardown_appcontext
def db_close(error=None):
    db._close()

# TODO: /verify : verification emails
# TODO: /verify/resend : resend verification emails
# TODO: /recover : recover password by emails
# TODO: /reset : reset password by emails
# TODO: /admin/repos : admin panel - repos display
# TODO: /repo/remove/<id> : repo removal for admin users
# TODO: /user/remove :  user removal for admin users
