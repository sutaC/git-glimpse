import sqlite3
import time
from app import DATABASE_PATH

def cleanup_expired_sessions():
    now = int(time.time()) 
    with sqlite3.connect(DATABASE_PATH) as connection:
        cursor = connection.cursor()
        cursor.execute("DELETE FROM `sessions` WHERE `expires` < ?;", (now,))
        connection.commit()
        print(f"Deleted {cursor.rowcount} expired sessions.")

if __name__ == "__main__":
    cleanup_expired_sessions()