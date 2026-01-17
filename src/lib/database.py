from secrets import token_urlsafe
from typing import Literal
from pathlib import Path
from flask import g
import lib.auth as auth
import sqlite3
import os

class Database:
    def __init__(self, path: Path) -> None:
        self.path: Path = path

    def init_db(self) -> None:
        cursor = self.connect().cursor()
        cursor.executescript('''
            -- roles
            CREATE TABLE IF NOT EXISTS `roles` (
                `id` TEXT PRIMARY KEY,
                `name` TEXT NOT NULL UNIQUE,
                `builds_repo_limit` INTEGER NOT NULL CHECK (`builds_repo_limit` > 0),
                `builds_user_limit` INTEGER NOT NULL CHECK (`builds_user_limit` > 0),
                `repo_limit` INTEGER NOT NULL CHECK (`repo_limit` > 0)
            );
            INSERT INTO roles (`id`, `name`, `builds_repo_limit`, `builds_user_limit`, `repo_limit`)
            VALUES
                ('u', 'User', 10, 30, 3),
                ('a', 'Admin', 100, 1000, 10)
            ON CONFLICT(`id`) DO NOTHING;                    
            -- users
            CREATE TABLE IF NOT EXISTS `users` (
                `id` INTEGER PRIMARY KEY,
                `login` TEXT NOT NULL UNIQUE,
                `email` TEXT NOT NULL UNIQUE,
                `password` TEXT NOT NULL,
                `is_verified` INTEGER NOT NULL DEFAULT 0 CHECK (`is_verified` IN (0, 1)),
                `role` TEXT NOT NULL DEFAULT 'u' REFERENCES `roles`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE
            );
            CREATE INDEX IF NOT EXISTS `idx_users_login` ON `users`(`login`);
            -- sessions
            CREATE TABLE IF NOT EXISTS `sessions` (
                `id` TEXT PRIMARY KEY,
                `user_id` TEXT NOT NULL REFERENCES `users`(`id`) ON DELETE CASCADE,
                `expires` INTEGER NOT NULL,
                UNIQUE(`user_id`, `id`)
            );
            CREATE INDEX IF NOT EXISTS `idx_sessions_expires` ON `sessions`(`expires`);
            CREATE INDEX IF NOT EXISTS `idx_sessions_user_id` ON `sessions`(`user_id`);
            -- repos
            CREATE TABLE IF NOT EXISTS `repos` (
                `id` TEXT PRIMARY KEY,
                `user_id` TEXT NOT NULL REFERENCES `users`(`id`) ON DELETE CASCADE,
                `url` TEXT NOT NULL,
                `repo_name` TEXT NOT NULL,
                `ssh_key` TEXT,
                `created` INTEGER NOT NULL DEFAULT (unixepoch()),
                UNIQUE(`user_id`, `url`)
            );
            CREATE INDEX IF NOT EXISTS `idx_repos_user_id` ON `repos`(`user_id`);
            -- builds
            CREATE TABLE IF NOT EXISTS `builds` (
                `id` INTEGER PRIMARY KEY,
                `user_id` TEXT NOT NULL REFERENCES `users`(`id`) ON DELETE CASCADE,
                `repo_id` TEXT REFERENCES `repos`(`id`) ON DELETE SET NULL,
                `timestamp` INTEGER NOT NULL DEFAULT (unixepoch()),
                `size` INTEGER NOT NULL CHECK (size >= 0)
            );
            CREATE INDEX IF NOT EXISTS `idx_builds_user_time` ON builds(`user_id`, `timestamp` DESC);
            CREATE INDEX IF NOT EXISTS `idx_builds_repo_time` ON builds(`repo_id`, `timestamp` DESC);
        ''')
        self.connect().commit()
        cursor.execute("SELECT `id` FROM `users` WHERE `login` = 'root';")
        root_id = cursor.fetchone()
        if not root_id:
            password = os.getenv("ROOT_PASSWORD") or "password"
            hashed_password = auth.hash_password(password)
            root_id = self.add_user("root", "", hashed_password, 'a')
            self.set_user_verified(root_id)
        cursor.close()
        self.close()
        self.path.chmod(0o600)

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
    
    def get_repo_user_id(self, repo_id:str) -> int | None:
        cursor = self.connect().cursor()
        cursor.execute('SELECT `user_id` FROM `repos` WHERE `id` = ?;', [repo_id])
        res = cursor.fetchone()
        cursor.close()
        return res[0] if res else None

    def get_repo_for_clone(self, repo_id:str) -> tuple[int, str, str] | None:
        cursor = self.connect().cursor()
        cursor.execute('SELECT `user_id`, `url`, `ssh_key` FROM `repos` WHERE `id` = ?;', [repo_id])
        res = cursor.fetchone()
        cursor.close()
        return res
    
    def get_repo(self, repo_id:str) -> tuple[str, str, int, int] | None:
        cursor = self.connect().cursor()
        cursor.execute('SELECT `repo_name`, `url`, `user_id`, `created` FROM `repos` WHERE `id` = ?;', [repo_id])
        res = cursor.fetchone()
        cursor.close()
        return res
    
    def is_repo_url_for_user(self, url:str, user_id:int) -> bool:
        cursor = self.connect().cursor()
        cursor.execute('SELECT `id` FROM `repos` WHERE `url` = ? AND `user_id` = ?;', [url, user_id])
        res = cursor.fetchone()
        cursor.close()
        return bool(res)

    def get_repo_count(self, user_id: int) -> int:
        cursor = self.connect().cursor()
        cursor.execute('SELECT COUNT(*) FROM `repos` WHERE `user_id` = ?;', [user_id])
        res = cursor.fetchone()
        cursor.close()
        return res[0]

    def delete_repo(self, repo_id: str) -> None:
        cursor = self.connect().cursor()
        cursor.execute('DELETE FROM `repos` WHERE `id` = ?;', [repo_id])
        self.connect().commit()
        cursor.close()

    def add_user(self, login:str, email:str, password:str, role:Literal['u','a'] = 'u') -> int:
        cursor = self.connect().cursor()
        cursor.execute('INSERT INTO `users` (`login`, `email`, `password`, `role`) VALUES (?, ?, ?, ?);', 
            [login, email, password, role]
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

    def is_user_login(self, login: str) -> bool:
        cursor = self.connect().cursor()
        cursor.execute('SELECT `id` FROM `users` WHERE `login` = ?;', [login])
        res = cursor.fetchone()
        cursor.close()
        return res is not None
    
    def is_user_email(self, email: str) -> bool:
        cursor = self.connect().cursor()
        cursor.execute('SELECT `id` FROM `users` WHERE `email` = ?;', [email])
        res = cursor.fetchone()
        cursor.close()
        return res is not None

    def get_user_password(self, login: str) -> tuple[int, str, str] | None:
        cursor = self.connect().cursor()
        cursor.execute('SELECT `id`, `password`, `role` FROM `users` WHERE `login` = ?;', [login])
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

    def delete_all_expired_sessions(self) -> None:
        cursor = self.connect().cursor()
        cursor.execute('DELETE FROM `sessions` WHERE `expires` < unixepoch();')
        self.connect().commit()        
        cursor.close()

    def delete_user_expired_sessions(self, user_id: int) -> None:
        cursor = self.connect().cursor()
        cursor.execute('DELETE FROM `sessions` WHERE `user_id` = ? AND `expires` < unixepoch();', [user_id])
        self.connect().commit()        
        cursor.close()

    def add_build(self, user_id: int, repo_id: str, size: int) -> None:
        cursor = self.connect().cursor()
        cursor.execute("INSERT INTO `builds` (`user_id`, `repo_id`, `size`) VALUES (?, ?, ?);", [user_id, repo_id, size])
        self.connect().commit()
        cursor.close()

    def get_latest_build(self, repo_id: str) -> tuple[int, int] | None:
        cursor = self.connect().cursor()
        cursor.execute("SELECT `timestamp`, `size` FROM `builds` WHERE `repo_id` = ? ORDER BY `timestamp` DESC LIMIT 1;", 
            [repo_id]
        )
        res = cursor.fetchone()
        cursor.close()
        return res
    
    def get_user_build_count(self, user_id: int) -> int:
        cursor = self.connect().cursor()
        # User builds younger than 1 week
        cursor.execute('''
            SELECT COUNT(*) FROM `builds` 
            WHERE `user_id` = ? AND `builds`.`timestamp` > unixepoch() - 7*24*3600;
        ''', [user_id])
        res = cursor.fetchone()
        cursor.close()
        return res[0]
    
    def get_repo_build_count(self, repo_id: str) -> int:
        cursor = self.connect().cursor()
        # Repo builds younger than 1 week
        cursor.execute('''
            SELECT COUNT(*) FROM `builds` 
            WHERE `repo_id` = ? AND `builds`.`timestamp` > unixepoch() - 7*24*3600;
        ''', [repo_id])
        res = cursor.fetchone()
        cursor.close()
        return res[0]
    
    def get_user_limits(self, user_id: int) -> tuple[int, int, int] | None:
        cursor = self.connect().cursor()
        cursor.execute('''
            SELECT `roles`.`builds_repo_limit`, `roles`.`builds_user_limit`, `roles`.`repo_limit` 
            FROM `users` JOIN `roles` ON `users`.`role` = `roles`.`id` 
            WHERE `users`.`id` = ?;
        ''', [user_id])
        res = cursor.fetchone()
        cursor.close()
        return res
