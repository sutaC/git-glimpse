from secrets import token_urlsafe
from pathlib import Path
from typing import Literal
import uuid
from flask import g
import sqlite3

class Database:
    def __init__(self, path: Path) -> None:
        self.path: Path = path

    def init_db(self) -> None:
        cursor = self.connect().cursor()
        cursor.executescript('''
            CREATE TABLE IF NOT EXISTS `users` (
                `id` TEXT PRIMARY KEY,
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
                `expires` TIMESTAMP NOT NULL,
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
            password = "" # TODO get from env
            salt = "" # TODO generate
            root_id = self.add_user("root", "", password, salt, 'a')
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
            id = token_urlsafe(12)
            if (repo_root_path /  id).exists(): continue
            cursor.execute('SELECT `id` FROM `repos` WHERE `id` = ?;', [id])
            if not cursor.fetchone(): break
        cursor.close()
        return id

    def add_repo(self, id:str, user_id:str, url:str, repo_name:str, ssh_key:str|None = None) -> None:
        cursor = self.connect().cursor()
        cursor.execute('INSERT INTO `repos` (`id`, `user_id`, `url`, `repo_name`, `ssh_key`) VALUES (?, ?, ?, ?, ?);', 
            [id, user_id, url, repo_name, ssh_key]
        )
        self.connect().commit()
        cursor.close()
    
    def get_all_repos(self) -> list[tuple[str, str]]:
        cursor = self.connect().cursor()
        cursor.execute("SELECT `id`, `repo_name` FROM `repos`;")
        res = cursor.fetchall()
        cursor.close()
        return res

    def get_repo_name(self, id:str) -> str | None:
        cursor = self.connect().cursor()
        cursor.execute('SELECT `repo_name` FROM `repos` WHERE `id` = ?;', [id])
        res = cursor.fetchone()
        cursor.close()
        return res[0] if res else None

    def add_user(self, login:str, email:str, password:str, salt:str, role:Literal['u','a'] = 'u') -> str:
        cursor = self.connect().cursor()
        while True:
            id = str(uuid.uuid4())
            cursor.execute('SELECT `id` FROM `users` WHERE `id` = ?;', [id])
            if not cursor.fetchone(): break
        cursor.execute('INSERT INTO `users` (`id`, `login`, `email`, `password`, `salt`, `role`) VALUES (?, ?, ?, ?, ?, ?);', 
            [id, login, email, password, salt, role]
        )
        self.connect().commit()
        cursor.close()
        return id

    def set_user_verified(self, id:str) -> None:
        cursor = self.connect().cursor()
        cursor.execute('UPDATE `users` SET `is_verified` = 1 WHERE `id` = ?;', [id])
        self.connect().commit()
        cursor.close()