from pathlib import Path
from flask import Flask, Response, render_template, abort, send_file, redirect

REPO_PATH =  Path(__file__).parent.parent / "repo" # /[...]/project_root/repo
if(not REPO_PATH.is_dir()): REPO_PATH.mkdir()

app = Flask(__name__)

@app.route("/")
def root():
    return render_template("index.html", msg="Hello World!")

@app.route("/repo/<string:id>", defaults={"sub": ""}, strict_slashes=False)
@app.route("/repo/<string:id>/<path:sub>")
def repo(id: str, sub: str):
    # TODO check for id scheme
    if len(id) != 8:
        abort(404)
    path = REPO_PATH / id
    if not path.is_dir():
        abort(404)
    subpath = Path(sub)
    path = (path / subpath).resolve()
    if not path.exists() or ".git" in path.parts or REPO_PATH not in path.parents:
        abort(404)
    # Makes list of path urls to all parent dirs
    parentchain = path.parts[path.parts.index(id)+1:-1]
    parentchain = ['/'.join(parentchain[:parentchain.index(p)+1]) for p in parentchain]
    # ---
    return render_template(
        "repo.html", 
        repo_name="repo-name", 
        path_str=str(subpath).lstrip("."),
        path=path,
        id=id,
        parent_chain=parentchain
    )

@app.route("/raw/<string:id>/<path:sub>")
def raw(id: str, sub: str):
    # TODO check for id scheme
    if len(id) != 8:
        abort(404)
    path = REPO_PATH / id
    if not path.is_dir():
        abort(404)
    subpath = Path(sub)
    path = (path / subpath).resolve()
    if not path.exists() or ".git" in path.parts or REPO_PATH not in path.parents:
        abort(404)
    if path.is_dir():
        return redirect(f"/repo/{id}/{sub}", 303)
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return Response(f.read(), mimetype="text/plain")

