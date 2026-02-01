from pathlib import Path

PROJECT_ROOT_PATH = Path(__file__).parent.parent 
DATABASE_PATH = PROJECT_ROOT_PATH / "database.db"
REPO_PATH =  PROJECT_ROOT_PATH / "repo"

REPO_PATH.mkdir(exist_ok=True)
