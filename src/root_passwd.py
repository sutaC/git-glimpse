from dotenv import load_dotenv
load_dotenv()
# ensures loaded .env in modules
from lib.utils import is_valid_password
from lib.auth import hash_password
from globals import DATABASE_PATH
from lib.database import Database
from getpass import getpass
from sys import exit

if __name__ == "__main__":
    print("Root user password change")
    password = getpass("Password: ")
    r_password = getpass("Repeat password: ")
    # check
    if password != r_password:
        print("Password does not match repeated password")
        exit(1)
    pass_err = is_valid_password(password)
    if pass_err:
        print(pass_err)
        exit(1)
    # Updates password
    db = Database(DATABASE_PATH, raw_mode=True)
    h_password = hash_password(password)
    rid: int | None = db._fetch_value("SELECT `id` FROM `users` WHERE `login` = 'root';")
    if rid == None: 
        print("Root user not found")
        exit(1)
    db.set_user_password(rid, h_password)
    db.delete_user_sessions(rid)
    db._close()
    print("Password changed")
