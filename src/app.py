from tempfile import NamedTemporaryFile
from flask import Flask, Response, render_template, abort, redirect, send_file, request, g
from lib.database import Database
from dotenv import load_dotenv
from pathlib import Path
import lib.utils as utils
import lib.auth as auth
import lib.git as git
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
    if not session: return db.close()
    user_id, expires = session
    if expires < int(time.time()):
        db.delete_user_expired_sessions(user_id)
        db.close()
        g.clear_session_cookie = True
        return 
    user = db.get_user(user_id)
    if not user:
        db.delete_user_expired_sessions(user_id)
        db.close()
        g.clear_session_cookie = True
        return
    db.close()
    user_login, role, is_verified = user
    g.user = auth.User(session_id, user_id, user_login, role, is_verified)

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
    if len(repo_id) != 22 or not repo_id.isascii():
        abort(404)
    repo_name = db.get_repo_name(repo_id)
    db.close()
    if not repo_name:
        abort(404)
    repo_path = REPO_PATH / repo_id
    if not repo_path.is_dir():
        abort(410, "Repo is not on server")
    subpath = Path(sub)
    try:
        path = git.get_repo_path(repo_path, subpath)
    except git.RepoError as e:
        abort(e.code, e.msg)
    print(path)
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
    db.close()
    if not repo_name: abort(404)
    repo_path = REPO_PATH / repo_id
    if not repo_path.is_dir():
        abort(410, "Repo is not on server")
    subpath = Path(sub)
    try:
        path = git.get_repo_path(repo_path, subpath)
    except git.RepoError as e:
        abort(e.code, e.msg)
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
    if not url:
        abort(400, "Missing url")
    ssh_key =  request.form.get("ssh_key")
    if ssh_key: ssh_key = ssh_key.strip()
    else: ssh_key = None
    if not utils.is_valid_repo_url(url):
        abort(400, "Invalid url")
    if db.is_repo_url_for_user(url, g.user.user_id):
        db.close()
        abort(400, "Repo with that url already exists for that user")
    limits = db.get_user_limits(g.user.user_id)
    if not limits:
        db.close()
        abort(500, "Could not resolve user limits")
    builds_repo_limit, builds_user_limit, repo_limit = limits
    user_repos = db.get_repo_count(g.user.user_id)
    if user_repos >= repo_limit:
        db.close()
        abort(400, f"Reached repo limit per user ({user_repos}/{repo_limit})")
    user_builds = db.get_user_build_count(g.user.user_id)
    if user_builds >= builds_user_limit:
        db.close()
        abort(400, f"Reached build limit per user ({user_builds}/{builds_user_limit})")
    repo_id = db.generate_repo_id(REPO_PATH)
    path = REPO_PATH / repo_id
    if url.startswith("https://") and ssh_key:
        abort(400, "To use ssh-key you need to provide ssh url")
    # adding repo
    if ssh_key: ssh_key = git.encrypt_ssh_key(ssh_key)
    repo_name = url.removesuffix(".git").rsplit("/",1)[-1]
    # build
    db.add_repo(repo_id, g.user.user_id, url, repo_name, ssh_key)
    build_id = db.add_build(g.user.user_id, repo_id)
    repo_size = None
    try:
        repo_size = git.clone_repo(url, path, ssh_key)
    except git.RepoError as re:
        db.update_build(build_id, re.type)
        db.close()
        git.remove_protected_dir(path)
        if re.type == 'f': abort(re.code, f"Build failed: {re.msg}")
        elif re.type == 'v': abort(re.code, f"Build detected violation of rules: {re.msg}")
    db.update_build(build_id, 's', repo_size)
    db.close()
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
    if not user: 
        db.close()
        abort(400, "Invalid login or password")
    user_id, user_password, user_role = user
    if not auth.check_password(send_password, user_password): 
        db.close()
        abort(400, "Invalid login or password")
    expires = auth.get_session_expiriation(user_role)
    session_id = db.add_session(user_id, expires)
    response = redirect("/dashboard")
    response.set_cookie("session_id", session_id, expires=expires, path='/', samesite='strict', httponly=True, secure=True)
    db.close()
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
    if pass_err:
        abort(400, pass_err)
    if db.is_user_login(user_login):
        db.close()
        abort(400, 'Login is already registered')
    if db.is_user_email(email):
        db.close()
        abort(400, 'Email is already registered')
    # TODO: send verification email
    hashed_password = auth.hash_password(password)
    user_id = db.add_user(user_login, email, hashed_password, 'u')
    expires = auth.get_session_expiriation('u')
    session_id = db.add_session(user_id, expires)
    response = redirect("/dashboard")
    response.set_cookie("session_id", session_id, expires=expires, path='/', samesite='strict', httponly=True, secure=True)
    db.close()
    return response

@app.route("/logout")
@auth.login_required()
def logout():
    db.delete_session(g.user.session_id)
    db.delete_user_expired_sessions(g.user.user_id)
    db.close()
    response = redirect("/login")
    response.delete_cookie("session_id")
    return response

# TODO: /verify : verification emails
# TODO: /verify/resend : resend verification emails
# TODO: /recover : recover password by emails
# TODO: /reset : reset password by emails
# TODO: /admin : admin panel (++)

@app.route("/dashboard")
@auth.login_required()
def dashboard():
    # TODO: verification message if not verified
    repos = db.get_all_user_repos(g.user.user_id)
    limits = db.get_user_limits(g.user.user_id)
    if not limits:
        db.close()
        abort(500, "Could not resolve user limits")
    builds_repo_limit, builds_user_limit, repo_limit = limits
    user_build_count = db.get_user_build_count(g.user.user_id)
    repo_count = db.get_repo_count(g.user.user_id)
    db.close()
    return render_template(
        "dashboard.html", 
        repos=repos, 
        builds_user_limit=builds_user_limit,
        user_build_count=user_build_count,
        repo_limit=repo_limit,
        repo_count=repo_count
    )

@app.route("/repo/details/<string:repo_id>")
@auth.login_required()
def details(repo_id: str):
    if len(repo_id) != 22 or not repo_id.isascii(): abort(404)
    repo = db.get_repo(repo_id)
    if not repo: 
        db.close()
        abort(404)
    repo_name, url, repo_user_id, created = repo
    if repo_user_id != g.user.user_id: 
        db.close()
        abort(404)
    build = db.get_latest_build(repo_id)
    build_timestamp = None
    build_size = None
    build_status = None
    if build: build_status, build_timestamp, build_size = build
    limits = db.get_user_limits(g.user.user_id)
    if not limits:
        db.close()
        abort(500, "Could not resolve user limits")
    builds_repo_limit, builds_user_limit, repo_limit = limits
    repo_build_count = db.get_repo_build_count(repo_id)
    db.close()
    return render_template(
        "details.html",
        repo_id=repo_id,
        repo_name=repo_name,
        url=url,
        created=utils.timestamp_to_str(created),
        build_status=("?" if build_status is None else utils.code_to_status(build_status)),
        build_timestamp=("?" if build_timestamp is None else utils.timestamp_to_str(build_timestamp)),
        build_size=("?" if build_size is None else utils.size_to_str(build_size)),
        builds_repo_limit=builds_repo_limit,
        repo_build_count=repo_build_count
    )

@app.route("/repo/build/<string:repo_id>")
def build(repo_id: str):
    if len(repo_id) != 22 or not repo_id.isascii(): abort(404)
    repo = db.get_repo_for_clone(repo_id)
    if not repo: abort(404)
    user_id, url, ssh_key = repo
    if user_id != g.user.user_id: abort(404)
    limits = db.get_user_limits(g.user.user_id)
    if not limits:
        db.close()
        abort(500, "Could not resolve user limits")
    builds_repo_limit, builds_user_limit, repo_limit = limits
    user_builds = db.get_user_build_count(g.user.user_id)
    if user_builds >= builds_user_limit:
        db.close()
        abort(400, f"Reached build limit per user ({user_builds}/{builds_user_limit})")
    repo_builds = db.get_repo_build_count(repo_id)
    if repo_builds >= builds_repo_limit:
        db.close()
        abort(400, f"Reached build limit per repo ({repo_builds}/{builds_repo_limit})")
    if db.has_repo_pending_build(repo_id):
        db.close()
        abort(400, "This repo already has pending build")
    # build
    path = REPO_PATH / repo_id
    if ssh_key: ssh_key = git.decrypt_ssh_key(ssh_key)
    build_id = db.add_build(g.user.user_id, repo_id)
    repo_size = None
    try:
        repo_size = git.clone_repo(url, path, ssh_key)
    except git.RepoError as re:
        db.update_build(build_id, re.type)
        db.close()
        git.remove_protected_dir(path)
        if re.type == 'f': abort(re.code, f"Build failed: {re.msg}")
        elif re.type == 'v': abort(re.code, f"Build detected violation of rules: {re.msg}")
    db.update_build(build_id, 's', repo_size)
    db.close()
    return redirect(f"/repo/details/{repo_id}")

@app.route("/repo/remove/<string:repo_id>")
def remove(repo_id: str):
    if len(repo_id) != 22 or not repo_id.isascii(): abort(404)
    user_id = db.get_repo_user_id(repo_id)
    if not user_id or user_id != g.user.user_id: abort(404)
    db.delete_repo(repo_id)
    db.close()
    path = REPO_PATH / repo_id
    try:
        if path.exists(): git.remove_protected_dir(path)
    except Exception as e:
        print(f"Removal failed: {e}")
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
    user_id, password, role = user
    if not auth.check_password(send_password, password):
        db.close()
        abort(404, "Incorrect password")
    repo_ids = db.get_all_user_repos(g.user.user_id)
    for rid, rname in repo_ids:
        git.remove_protected_dir(REPO_PATH / rid)
    db.delete_user(g.user.user_id)
    db.close()
    return redirect("/login")

@app.teardown_appcontext
def db_close(error=None):
    db.close()