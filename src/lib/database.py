from secrets import token_urlsafe
from typing import Literal
from pathlib import Path
from flask import g
import sqlite3
import lib.auth as auth
import os

class Database:
    def __init__(self, path: Path) -> None:
        self.path: Path = path

    def init_db(self) -> None:
        cursor = self.connect().cursor()
        cursor.executescript('''
            CREATE TABLE IF NOT EXISTS `users` (
                `id` INTEGER PRIMARY KEY,
                `login` TEXT NOT NULL UNIQUE,
                `email` TEXT NOT NULL UNIQUE,
                `password` TEXT NOT NULL,
                `salt` TEXT NOT NULL,
                `is_verified` INTEGER NOT NULL DEFAULT 0 CHECK (`is_verified` IN (0, 1)),
                `role` TEXT DEFAULT 'u' NOT NULL CHECK (`role` IN ('u', 'a'))
            );
            CREATE TABLE IF NOT EXISTS sessions (
                `id` TEXT PRIMARY KEY,
                `user_id` TEXT NOT NULL REFERENCES `users`(`id`) ON DELETE CASCADE,
                `expires` INTEGER NOT NULL,
                UNIQUE(`user_id`, `id`)
            );
            CREATE INDEX IF NOT EXISTS `idx_sessions_user_id` ON `sessions`(`user_id`);
            CREATE TABLE IF NOT EXISTS `repos` (
                `id` TEXT PRIMARY KEY,
                `user_id` TEXT NOT NULL REFERENCES `users`(`id`) ON DELETE CASCADE,
                `url` TEXT NOT NULL,
                `repo_name` TEXT NOT NULL,
                `ssh_key` TEXT,
                UNIQUE(`user_id`, `url`)
            );
            CREATE INDEX IF NOT EXISTS `idx_repos_user_id` ON `repos`(`user_id`);
        ''')
        self.connect().commit()
        cursor.execute("SELECT `id` FROM `users` WHERE `login` = 'root';")
        root_id = cursor.fetchone()
        if not root_id:
            password = os.getenv("ROOT_PASSWORD") or "password"
            salt = auth.generate_salt()
            hashed_password = auth.hash_password(password, salt)
            root_id = self.add_user("root", "", hashed_password, salt, 'a')
            self.set_user_verified(root_id)
        cursor.close()
        self.close()

    def connect(self) -> sqlite3.Connection:
        if "db" not in g:
            g.db = sqlite3.connect(self.path)
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys = ON")
        return g.db
        
    def close(self) -> None:
        db = g.pop("db", None)
        if db: db.close()

    def generate_repo_id(self, repo_root_path: Path) -> str:
        cursor = self.connect().cursor()
        while True:
            id = token_urlsafe(16)
            if (repo_root_path /  id).exists(): continue
            cursor.execute('SELECT `id` FROM `repos` WHERE `id` = ?;', [id])
            if not cursor.fetchone(): break
        cursor.close()
        return id

    def add_repo(self, repo_id:str, user_id:int, url:str, repo_name:str, ssh_key:str|None = None) -> None:
        cursor = self.connect().cursor()
        cursor.execute('INSERT INTO `repos` (`id`, `user_id`, `url`, `repo_name`, `ssh_key`) VALUES (?, ?, ?, ?, ?);', 
            [repo_id, user_id, url, repo_name, ssh_key]
        )
        self.connect().commit()
        cursor.close()
    
    def get_all_user_repos(self, user_id: int) -> list[tuple[str, str]]:
        cursor = self.connect().cursor()
        cursor.execute('''
            SELECT `repos`.`id`, `repos`.`repo_name` 
            FROM `users` 
            JOIN `repos` ON  `users`.`id` = `repos`.`user_id`
            WHERE `users`.`id` = ?;
        ''', [user_id])
        res = cursor.fetchall()
        cursor.close()
        return res

    def get_repo_name(self, repo_id:str) -> str | None:
        cursor = self.connect().cursor()
        cursor.execute('SELECT `repo_name` FROM `repos` WHERE `id` = ?;', [repo_id])
        res = cursor.fetchone()
        cursor.close()
        return res[0] if res else None

    def add_user(self, login:str, email:str, password:str, salt:str, role:Literal['u','a'] = 'u') -> int:
        cursor = self.connect().cursor()
        cursor.execute('INSERT INTO `users` (`login`, `email`, `password`, `salt`, `role`) VALUES (?, ?, ?, ?, ?);', 
            [login, email, password, salt, role]
        )
        user_id = cursor.lastrowid
        assert isinstance(user_id, int)
        self.connect().commit()
        cursor.close()
        return user_id

    def set_user_verified(self, user_id:int) -> None:
        cursor = self.connect().cursor()
        cursor.execute('UPDATE `users` SET `is_verified` = 1 WHERE `id` = ?;', [user_id])
        self.connect().commit()
        cursor.close()

    def get_user_password(self, login: str) -> tuple[int, str, str, str] | None:
        cursor = self.connect().cursor()
        cursor.execute('SELECT `id`, `password`, `salt`, `role` FROM `users` WHERE `login` = ?;', [login])
        res = cursor.fetchone()
        cursor.close()
        return res
    
    def get_user(self, user_id: int) -> tuple[str, str, bool] | None:
        cursor = self.connect().cursor()
        cursor.execute('SELECT `login`, `role`, `is_verified` FROM `users` WHERE `id` = ?;', [user_id])
        res = cursor.fetchone()
        cursor.close()
        return res
    
    def add_session(self, user_id: int, expires: int) -> str:
        cursor = self.connect().cursor()
        id = token_urlsafe(32)
        cursor.execute('INSERT INTO `sessions` (`id`, `user_id`, `expires`) VALUES (?, ?, ?);', [id, user_id, expires])
        self.connect().commit()
        cursor.close()
        return id
    
    def get_session(self, session_id: str) -> tuple[int, int] | None:
        cursor = self.connect().cursor()
        cursor.execute('SELECT `user_id`, `expires` FROM `sessions` WHERE `id` = ?;', [session_id])
        res = cursor.fetchone()
        cursor.close()
        return res
    
    def delete_session(self, session_id: str) -> tuple[str, int] | None:
        cursor = self.connect().cursor()
        cursor.execute('DELETE FROM `sessions` WHERE `id` = ?;', [session_id])
        self.connect().commit()        
        cursor.close()