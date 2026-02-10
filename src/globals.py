from pathlib import Path

PROJECT_ROOT_PATH = Path(__file__).parent.parent 
DATA_PATH = PROJECT_ROOT_PATH / "data"

REPO_PATH =  DATA_PATH / "repos"
DATABASE_PATH = DATA_PATH / "db.sqlite"
SIZE_CACHE_PATH = DATA_PATH / ".size.json"
CLEANUP_CACHE_PATH = DATA_PATH / ".cleanup.json"

DATA_PATH.mkdir(exist_ok=True)
REPO_PATH.mkdir(exist_ok=True)
