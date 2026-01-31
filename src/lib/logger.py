from datetime import datetime
import os

ENV = os.environ.get("ENV")

# TODO: Expand logger

def log(msg: str, type: str = "DEBUG"):
    if ENV == 'prod' and type == "DEBUG": return
    print(f"{datetime.now().isoformat()} :: {type} :: {msg}")