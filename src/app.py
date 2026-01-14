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
        abort(500, "Repo is not on server")
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

@app.route("/raw/<string:repo_id>/<path:sub>")
def raw(repo_id: str, sub: str):
    if len(repo_id) != 22 or not repo_id.isascii(): abort(404)
    repo_name = db.get_repo_name(repo_id)
    db.close()
    if not repo_name: abort(404)
    repo_path = REPO_PATH / repo_id
    if not repo_path.is_dir():
        abort(500, "Repo is not on server")
    subpath = Path(sub)
    try:
        path = git.get_repo_path(repo_path, subpath)
    except git.RepoError as e:
        abort(e.code, e.msg)
    if path.is_dir():
        return redirect(f"/repo/{repo_id}/{sub}", 303)
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
    # TODO check limits
    repo_id = db.generate_repo_id(REPO_PATH)
    path = REPO_PATH / repo_id
    if url.startswith("https://") and ssh_key:
        abort(400, "To use ssh-key you need to provide ssh url")
    try:
        git.clone_repo(url, path, ssh_key)
    except Exception as e:
        print(f"Cloning faield: {e}")
        abort(400, "Could not clone repo, check key if its private")
    repo_name = url.removesuffix(".git").rsplit("/",1)[-1]
    if ssh_key: ssh_key = git.encrypt_ssh_key(ssh_key)
    db.add_repo(repo_id, g.user.user_id, url, repo_name, ssh_key)
    db.close()
    return redirect(f"/repo/{repo_id}/")

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
    return render_template("dashboard.html", repos=repos)

@app.route("/repo/details/<string:repo_id>")
@auth.login_required()
def details(repo_id: str):
    if len(repo_id) != 22 or not repo_id.isascii(): abort(404)
    repo = db.get_repo(repo_id)
    if not repo: abort(404)
    repo_name, repo_user_id = repo
    if repo_user_id != g.user.user_id: abort(404)
    # TODO: basic information, editing and building 
    return render_template("details.html", repo_name=repo_name)
    
@app.teardown_appcontext
def db_close(error=None):
    db.close()