from pathlib import Path
from flask import Flask, Response, render_template, abort, redirect, request, send_file
from lib.database import Database
import lib.git as git
from lib.utils import is_text

DATABASE_PATH = Path(__file__).parent.parent / "database.db"
REPO_PATH =  Path(__file__).parent.parent / "repo" # /[...]/project_root/repo
if(not REPO_PATH.is_dir()): REPO_PATH.mkdir()

app = Flask(__name__)
db = Database(DATABASE_PATH)
with app.app_context():
    db.init_db()

@app.route("/")
def root():
    repos = db.get_all_repos()
    db.close()
    return render_template("index.html", repos=repos)

@app.route("/repo/<string:id>", defaults={"sub": ""}, strict_slashes=False)
@app.route("/repo/<string:id>/<path:sub>")
def repo(id: str, sub: str):
    if len(id) != 16 or not id.isascii():
        abort(404)
    repo_name = db.get_repo_name(id)
    db.close()
    if not repo_name:
        abort(404)
    path = REPO_PATH / id
    if not path.is_dir():
        # TODO hadnle error - repo in db exists but dir not 
        abort(409, "Repo is not cloned on server")
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
    if len(id) != 16 or not id.isascii():
        abort(404)
    repo_name = db.get_repo_name(id)
    db.close()
    if not repo_name:
        abort(404)
    path = REPO_PATH / id
    if not path.is_dir():
        # TODO hadnle error - repo in db exists but dir not 
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
def repo_add():
    if request.method == "GET":
        return render_template("repo_add.html")
    # POST:
    url = request.form["url"]
    ssh_key =  request.form["ssh_key"] if request.form["ssh_key"] else None
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
        # TODO: better error msg
        abort(400, "Could not clone repo")
    repo_name = url.removesuffix(".git").rsplit("/",1)[-1]
    db.add_repo(repo_id, user_id, url, repo_name, ssh_key)
    db.close()
    return redirect(f"/repo/{repo_id}/")

@app.teardown_appcontext
def db_close(error=None):
    db.close()