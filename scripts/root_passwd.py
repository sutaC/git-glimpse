# Add the project src folder to Python path
from pathlib import Path
import sys
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
# Load .env in modules
from dotenv import load_dotenv
load_dotenv()
# Imporst
from src.lib.utils import is_valid_password
from src.lib.auth import hash_password
from src.globals import DATABASE_PATH
from src.lib.database import Database
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--password", help="Root password", required=True, type=str)
    args = parser.parse_args()
    password: str = args.password
    # check
    pass_err = is_valid_password(password)
    if pass_err:
        print(pass_err)
        sys.exit(1)
    # Updates password
    db = Database(DATABASE_PATH, raw_mode=True)
    h_password = hash_password(password)
    rid: int | None = db._fetch_value("SELECT `id` FROM `users` WHERE `login` = 'root';")
    if rid == None: 
        print("Root user not found")
        sys.exit(1)
    db.set_user_password(rid, h_password)
    db.delete_user_sessions(rid)
    db._close()
    print("Password changed")
