from pathlib import Path
from flask import Flask, render_template, abort

REPO_PATH =  Path(__file__).parent.parent / "repo" # project_root / repo
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
    path /= subpath
    if not path.exists() or ".git" in path.parts:
        abort(404)
    str(subpath).lstrip(".")
    return render_template(
        "repo.html", 
        name="repo-name", 
        pathname=str(subpath).lstrip("."),
        path=path,
        id=id,
        parentchain=path.parts[path.parts.index(id)+1:-1]
    )
