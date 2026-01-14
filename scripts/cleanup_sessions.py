from pathlib import Path
import sqlite3
import time

DATABASE_PATH = Path(__file__).parent.parent / "database.db"

def main():
    if not DATABASE_PATH.exists():
        print("Database file does not exist")
        return
    now = int(time.time()) 
    with sqlite3.connect(DATABASE_PATH) as connection:
        cursor = connection.cursor()
        cursor.execute("DELETE FROM `sessions` WHERE `expires` < ?;", (now,))
        connection.commit()
        print(f"Deleted {cursor.rowcount} expired sessions.")

if __name__ == "__main__":
    main()