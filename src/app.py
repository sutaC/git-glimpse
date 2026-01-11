from pathlib import Path
from flask import Flask, render_template, abort

REPO_PATH =  Path(__file__).parent / "repo"
if(not REPO_PATH.is_dir()): REPO_PATH.mkdir()

app = Flask(__name__)

@app.route("/")
def root():
    return render_template("index.html", msg="Hello World!")

@app.route("/repo/<string:id>", defaults={"subpath": ""}, strict_slashes=False)
@app.route("/repo/<string:id>/<path:subpath>")
def repo(id: str, subpath: str):
    # TODO check for id scheme
    if len(id) != 8:
        abort(404)
    pth = REPO_PATH / id
    if not pth.is_dir():
        abort(404)
    pth /= Path(subpath)
    if not pth.exists():
        abort(404)
        
    return render_template(
        "repo.html", 
        name="name", 
        pathname=str(Path(subpath)).lstrip("."),
        path=pth,
        parentchain=subpath.split("/")[:-1]
    )
