from flask import Flask, Response, render_template, abort, redirect, send_file, request, g
from lib.database import Database
from dotenv import load_dotenv
from lib.utils import is_text
from pathlib import Path
import lib.auth as auth
import lib.git as git
import time

load_dotenv()

DATABASE_PATH = Path(__file__).parent.parent / "database.db"
REPO_PATH =  Path(__file__).parent.parent / "repo" # /[...]/project_root/repo
if(not REPO_PATH.is_dir()): REPO_PATH.mkdir()

app = Flask(__name__)
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
        db.delete_session(session_id)
        db.close()
        g.clear_session_cookie = True
        return 
    user = db.get_user(user_id)
    if not user:
        db.delete_session(session_id)
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

@app.route("/repo/<string:id>", defaults={"sub": ""}, strict_slashes=False)
@app.route("/repo/<string:id>/<path:sub>")
def repo(id: str, sub: str):
    if len(id) != 22 or not id.isascii():
        abort(404)
    repo_name = db.get_repo_name(id)
    db.close()
    if not repo_name:
        abort(404)
    path = REPO_PATH / id
    if not path.is_dir():
        abort(409, "Repo is not cloned on server, do a build first")
    subpath = Path(sub)
    path = (path / subpath).resolve()
    if not path.exists() or ".git" in path.parts or REPO_PATH not in path.parents:
        abort(404)
    # Makes list of path urls to all parent dirs
    parentchain = path.parts[path.parts.index(id)+1:-1]
    parentchain = ['/'.join(parentchain[:parentchain.index(p)+1]) for p in parentchain]
    return render_template(
        "repo.html", 
        repo_name=repo_name,
        path_str=str(subpath).lstrip("."),
        path=path,
        id=id,
        parent_chain=parentchain,
        is_text=is_text(path)
    )

@app.route("/raw/<string:id>/<path:sub>")
def raw(id: str, sub: str):
    if len(id) != 22 or not id.isascii(): abort(404)
    repo_name = db.get_repo_name(id)
    db.close()
    if not repo_name: abort(404)
    path = REPO_PATH / id
    if not path.is_dir():
        abort(409, "Repo is not cloned on server")
    subpath = Path(sub)
    path = (path / subpath).resolve()
    if not path.exists() or ".git" in path.parts or REPO_PATH not in path.parents:
        abort(404)
    if path.is_dir():
        return redirect(f"/repo/{id}/{sub}", 303)
    if is_text(path):
        with open(path, "r",) as f:
            return Response(f.read(), mimetype="text/plain")
    return send_file(path)

@app.route("/repo/add", methods=["GET", "POST"])
@auth.login_required()
def repo_add():
    if request.method == "GET":
        return render_template("repo_add.html")
    # POST:
    url = request.form.get("url", "").strip()
    if not url:
        abort(400, "Missing url")
    ssh_key =  request.form.get("ssh_key")
    if ssh_key: ssh_key = ssh_key.strip()
    else: ssh_key = None
    if not git.is_valid_repo_url(url):
        abort(400, "Invalid url")
    user_id = db.connect().execute("SELECT `id` FROM `users` WHERE `login` = 'root';").fetchone()[0] # DEBUG
    # TODO check limits
    repo_id = db.generate_repo_id(REPO_PATH)
    path = REPO_PATH / repo_id
    if url.startswith("https://") and ssh_key:
        abort(400, "To use ssh_ key you need to provide ssh url")
    try:
        git.clone_repo(url, path, ssh_key)
    except:
        abort(400, "Could not clone repo, check key if its private")
    repo_name = url.removesuffix(".git").rsplit("/",1)[-1]
    db.add_repo(repo_id, user_id, url, repo_name, ssh_key)
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
    user_id, password, salt, role = user
    hashed_password = auth.hash_password(send_password, salt)
    if password != hashed_password: 
        db.close()
        abort(400, "Invalid login or password")
    expires = int(time.time()) + (3600 if role == 'u' else 1200) # now + 1h (user) + 20min (admin) 
    session_id = db.add_session(user_id, expires)
    response = redirect("/dashboard")
    response.set_cookie("session_id", session_id, expires=expires, path='/', samesite='strict', httponly=True, secure=True)
    db.close()
    return response

@app.route("/logout")
@auth.login_required()
def logout():
    response = redirect("/login")
    response.delete_cookie("session_id")
    return response

@app.route("/dashboard")
@auth.login_required()
def dashboard():
    repos = db.get_all_user_repos(g.user.user_id)
    return render_template("dashboard.html", repos=repos)

@app.teardown_appcontext
def db_close(error=None):
    db.close()