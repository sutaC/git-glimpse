from lib.database_rows import Build, BuildActivity, Limits, Repo, RepoActivity, RepoClone, RepoRow, RoleType, RowType, Session, Sizes, User, UserActivity, UserAuth
from secrets import token_urlsafe
from pathlib import Path
from flask import g
import lib.auth as auth
import sqlite3
import os


class Database:
    def __init__(self, path: Path) -> None:
        self.path: Path = path

    # --- helpers
    def init_db(self) -> None:
        cursor = self._cursor()
        cursor.executescript('''
            -- roles
            CREATE TABLE IF NOT EXISTS `roles` (
                `id` TEXT PRIMARY KEY,
                `name` TEXT NOT NULL UNIQUE,
                `builds_user_limit` INTEGER NOT NULL CHECK (`builds_user_limit` > 0),
                `repo_limit` INTEGER NOT NULL CHECK (`repo_limit` > 0)
            );
            INSERT INTO roles (`id`, `name`, `builds_user_limit`, `repo_limit`)
            VALUES
                ('u', 'User', 10, 3),
                ('a', 'Admin', 100, 10)
            ON CONFLICT(`id`) DO NOTHING;                    
            -- users
            CREATE TABLE IF NOT EXISTS `users` (
                `id` INTEGER PRIMARY KEY,
                `login` TEXT NOT NULL UNIQUE,
                `email` TEXT NOT NULL UNIQUE,
                `password` TEXT NOT NULL,
                `is_verified` INTEGER NOT NULL DEFAULT 0 CHECK (`is_verified` IN (0, 1)),
                `role` TEXT NOT NULL DEFAULT 'u' REFERENCES `roles`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE,
                `created` INTEGER NOT NULL DEFAULT (unixepoch())
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
                `status` TEXT NOT NULL DEFAULT 'p' CHECK (`status` IN ('s', 'p', 'f', 'v')), 
                `timestamp` INTEGER NOT NULL DEFAULT (unixepoch()),
                `size` INTEGER CHECK (`size` >= 0),
                `archive_size` INTEGER CHECK (`archive_size` >= 0)
            );
            CREATE INDEX IF NOT EXISTS `idx_builds_user_time` ON builds(`user_id`, `timestamp` DESC);
            CREATE INDEX IF NOT EXISTS `idx_builds_repo_time` ON builds(`repo_id`, `timestamp` DESC);
        ''')
        self._commit()
        cursor.execute("SELECT `id` FROM `users` WHERE `login` = 'root';")
        root_id = cursor.fetchone()
        if not root_id:
            password = os.getenv("ROOT_PASSWORD") or "password"
            hashed_password = auth.hash_password(password)
            root_id = self.add_user("root", "", hashed_password, 'a')
            self.set_user_verified(root_id)
        self.path.chmod(0o600)

    def _connect(self) -> sqlite3.Connection:
        if "db" not in g:
            g.db = sqlite3.connect(self.path)
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys = ON")
        return g.db

    def _commit(self) -> None:
        self._connect().commit()

    def _cursor(self) -> sqlite3.Cursor:
        return self._connect().cursor()

    def _fetch_one(self, sql: str, params: tuple = (), row_type: type[RowType] = dict) -> RowType | None:
        row = self._cursor().execute(sql, params).fetchone()
        return row_type(*row) if row else None

    def _fetch_all(self, sql: str, params: tuple = (), row_type: type[RowType] = dict) -> list[RowType]:
        rows = self._cursor().execute(sql, params).fetchall()
        return [row_type(*row) for row in rows]

    def _fetch_value(self, sql: str, params: tuple = ()):
        row = self._cursor().execute(sql, params).fetchone()
        return row[0] if row else None

    def _fetch_count(self, query: str, params: tuple = ()) -> int:
        row = self._cursor().execute(query, params).fetchone()
        return row[0] if row else 0

    def _fetch_exists(self, query: str, params: tuple = ()) -> bool:
        row = self._cursor().execute(query, params).fetchone()
        return bool(row)

    def _close(self) -> None:
        db = g.pop("db", None)
        if db: db.close()

    # --- repos
    def add_repo(self, user_id: int, url: str, repo_name: str, ssh_key: str | None = None) -> str:
        repo_id = token_urlsafe(16)
        self._cursor().execute(
            'INSERT INTO `repos` (`id`, `user_id`, `url`, `repo_name`, `ssh_key`) VALUES (?, ?, ?, ?, ?);', 
            (repo_id, user_id, url, repo_name, ssh_key)
        )
        self._commit()
        return repo_id

    def list_user_repos(self, user_id: int) -> list[RepoRow]:
        return self._fetch_all('''
            SELECT `repos`.`id`, `repos`.`repo_name` 
            FROM `users` 
            JOIN `repos` ON  `users`.`id` = `repos`.`user_id`
            WHERE `users`.`id` = ?;
        ''', (user_id,), RepoRow
        )

    def list_repos(
            self, 
            offset:int=0, 
            limit:int=10,
            status: str='', 
            user: str='',
            repo: str = '',
            url: str = '',
            key: str = ''
        ) -> list[RepoActivity]:
        if offset < 0: offset = 0
        if limit < 0: limit = 0
        if not status in ['p', 's', 'v', 'f', '']: status = ''
        if not key in ['1', '0', '']: key = ''
        return self._fetch_all('''
            SELECT  `r`.`id`, `u`.`id`, `u`.`login`, `r`.`url`, (`r`.`ssh_key` IS NOT NULL) AS `has_key`, `r`.`created`,
                    `lb`.`status`, `lb`.`size`, `lb`.`timestamp`           
            FROM `repos` AS `r`
            JOIN `users` AS `u` ON `r`.`user_id` = `u`.`id`
            LEFT JOIN (
                SELECT `b`.`repo_id`, `b`.`status`, `b`.`size`, MAX(`b`.`timestamp`) AS `timestamp`
                FROM `builds` AS `b`
                GROUP BY `b`.`repo_id`
            ) AS `lb` ON `r`.`id` = `lb`.`repo_id`
            WHERE `r`.`id` LIKE ?
            AND `lb`.`status` LIKE ?
            AND `u`.`login` LIKE ?
            AND `r`.`url` LIKE ?
            AND `has_key` LIKE ?
            ORDER BY `lb`.`timestamp` DESC
            LIMIT ?, ?;
        ''', (repo or '%', status or '%', user or '%', url or '%', key or '%', offset, limit), row_type=RepoActivity)

    def get_repo_name(self, repo_id: str) -> str | None:
        return self._fetch_value('SELECT `repo_name` FROM `repos` WHERE `id` = ?;', (repo_id,))
    
    def get_repo_user_id(self, repo_id: str) -> int | None:
        return self._fetch_value('SELECT `user_id` FROM `repos` WHERE `id` = ?;', (repo_id,))

    def get_repo_for_clone(self, repo_id: str) -> RepoClone | None:
        return self._fetch_one('SELECT `user_id`, `url`, `ssh_key` FROM `repos` WHERE `id` = ?;', (repo_id,), RepoClone)
    
    def get_repo(self, repo_id: str) -> Repo | None:
        return self._fetch_one('SELECT `repo_name`, `url`, `user_id`, `created` FROM `repos` WHERE `id` = ?;', (repo_id,), Repo)
    
    def is_repo_url_for_user(self, url: str, user_id: int) -> bool:
        return self._fetch_exists('SELECT 1 FROM `repos` WHERE `url` = ? AND `user_id` = ?;', (url, user_id))

    def count_user_repos(self, user_id: int) -> int:
        return self._fetch_count('SELECT COUNT(*) FROM `repos` WHERE `user_id` = ?;', (user_id,))

    def delete_repo(self, repo_id: str) -> None:
        self._cursor().execute('DELETE FROM `repos` WHERE `id` = ?;', (repo_id,))
        self._commit()

    def count_repos(self) -> int:
        return self._fetch_count('SELECT COUNT(*) FROM `repos`;')

    # --- users
    def add_user(self, login: str, email: str, password: str, role: RoleType = 'u') -> int:
        cursor = self._cursor()
        cursor.execute('INSERT INTO `users` (`login`, `email`, `password`, `role`) VALUES (?, ?, ?, ?);', 
            (login, email, password, role)
        )
        self._commit()
        user_id = cursor.lastrowid
        assert isinstance(user_id, int)
        return user_id

    def set_user_verified(self, user_id: int, verified: bool = True) -> None:
        self._cursor().execute(
            'UPDATE `users` SET `is_verified` = ? WHERE `id` = ?;',
            ((1 if verified else 0), user_id)
        )
        self._commit()

    def set_user_role(self, user_id: int, role: RoleType = 'u') -> None:
        assert role in ['a', 'u']
        self._cursor().execute(
            'UPDATE `users` SET `role` = ? WHERE `id` = ?;',
            (role, user_id)
        )
        self._commit()

    def is_user_login(self, login: str) -> bool:
        return self._fetch_exists('SELECT 1 FROM `users` WHERE `login` = ?;', (login,))
    
    def is_user_email(self, email: str) -> bool:
        return self._fetch_exists('SELECT 1 FROM `users` WHERE `email` = ?;', (email,))

    def get_user_password(self, login: str) -> UserAuth | None:
        return self._fetch_one('SELECT `id`, `password`, `role` FROM `users` WHERE `login` = ?;', (login,), UserAuth)
    
    def get_user_login(self, user_id: int) -> str | None:
        return self._fetch_value('SELECT `login` FROM `users` WHERE `id` = ?;', (user_id,))

    def get_user(self, user_id: int) -> User | None:
        return self._fetch_one('SELECT `login`, `role`, `is_verified` FROM `users` WHERE `id` = ?;', (user_id,), User)
    
    def delete_user(self, user_id: int) -> None:
        self._cursor().execute('DELETE FROM `users` WHERE `id` = ?;', (user_id,))
        self._commit()
    
    def get_user_email(self, user_id: int) -> str | None:
        return self._fetch_value('SELECT `email` FROM `users` WHERE `id` = ?;', (user_id,)) 
    
    def get_user_limits(self, user_id: int) -> Limits | None:
        return self._fetch_one('''
            SELECT `roles`.`builds_user_limit`, `roles`.`repo_limit` 
            FROM `users` JOIN `roles` ON `users`.`role` = `roles`.`id` 
            WHERE `users`.`id` = ?;
        ''', (user_id,), Limits)

    def count_users(self) -> int:
        return self._fetch_count('SELECT COUNT(*) FROM `users`;')

    def list_users(
        self, 
        offset: int = 0, 
        limit: int = 10,
        login: str = '',
        email: str = '',
        role: str = '',
        is_verified: str = ''
    ) -> list[UserActivity]:
        if role not in ['a', 'u', '']: role = '' 
        if is_verified not in ['1', '0', '']: is_verified = '' 
        return self._fetch_all('''
            SELECT  `id`, `login`, `email`, `is_verified`, `role`, `created`
            FROM `users`
            WHERE `login` LIKE ?
            AND `email` LIKE ?
            AND `is_verified` LIKE ?
            AND `role` LIKE ?
            ORDER BY `created` DESC
            LIMIT ?, ?;
        ''', (login or '%', email or '%', is_verified or '%', role or '%', offset, limit), row_type=UserActivity)

    # --- sessions
    def add_session(self, user_id: int, expires: int) -> str:
        id = token_urlsafe(32)
        self._cursor().execute('INSERT INTO `sessions` (`id`, `user_id`, `expires`) VALUES (?, ?, ?);', (id, user_id, expires))
        self._commit()
        return id
    
    def get_session(self, session_id: str) -> Session | None:
        return self._fetch_one('SELECT `user_id`, `expires` FROM `sessions` WHERE `id` = ?;', (session_id,), Session)
    
    def delete_session(self, session_id: str) -> None:
        self._cursor().execute('DELETE FROM `sessions` WHERE `id` = ?;', (session_id,))
        self._commit()

    def delete_all_expired_sessions(self) -> None:
        self._cursor().execute('DELETE FROM `sessions` WHERE `expires` < unixepoch();')
        self._commit()

    def delete_user_expired_sessions(self, user_id: int) -> None:
        self._cursor().execute('DELETE FROM `sessions` WHERE `user_id` = ? AND `expires` < unixepoch();', (user_id,))
        self._commit()        

    # --- builds
    def add_build(self, user_id: int, repo_id: str) -> int:
        cursor = self._cursor()
        cursor.execute('INSERT INTO `builds` (`user_id`, `repo_id`) VALUES (?, ?);', (user_id, repo_id))
        self._commit()
        build_id = cursor.lastrowid
        assert isinstance(build_id, int)
        return build_id
    
    def update_build(self, build_id: int, status: str, size: int | None = None, archive_size:  int | None = None) -> None:
        self._cursor().execute('''
            UPDATE `builds` SET `status` = ?, `size` = ?, `archive_size` = ? WHERE `id` = ?;
        ''', [status, size, archive_size, build_id])
        self._commit()

    def has_repo_pending_build(self, repo_id: str) -> bool:
        return self._fetch_exists("SELECT 1 FROM `builds` WHERE `status` = 'p' AND `repo_id` = ? LIMIT 1;", (repo_id,))

    def get_latest_build(self, repo_id: str) -> Build | None:
        return self._fetch_one(
            'SELECT `status`, `timestamp`, `size` FROM `builds` WHERE `repo_id` = ? ORDER BY `timestamp` DESC LIMIT 1;', 
            (repo_id,), Build
        )
    
    def count_user_builds(self, user_id: int) -> int:
        return self._fetch_count('''
            SELECT COUNT(*) FROM `builds` 
            WHERE `user_id` = ? AND `builds`.`timestamp` > unixepoch() - 7*24*3600;
        ''', (user_id,)
        )
    
    def count_repo_builds(self, repo_id: str) -> int:
        return self._fetch_count('''
            SELECT COUNT(*) FROM `builds` WHERE `repo_id` = ? AND `timestamp` > unixepoch() - 7*24*3600;
        ''', (repo_id,)
        )
    
    def count_last24h_builds(self) -> int:
        return self._fetch_count('SELECT COUNT(*) FROM `builds` WHERE `timestamp` > unixepoch() - 24*3600')
    
    def count_last7d_builds(self) -> int:
        return self._fetch_count('SELECT COUNT(*) FROM `builds` WHERE `timestamp` > unixepoch() - 7*24*3600')

    def sum_build_sizes(self) -> Sizes:
        r = self._fetch_one('''
            SELECT COALESCE(SUM(`b`.`size`), 0), COALESCE(SUM(`b`.`archive_size`), 0)
            FROM `builds` AS `b`
            JOIN `repos` ON `b`.`repo_id` = `repos`.`id`
            JOIN (
                SELECT `b2`.`repo_id`, MAX(`b2`.`timestamp`) AS `timestamp`
                FROM `builds` AS `b2`
                GROUP BY `b2`.`repo_id`
            ) AS `latest_builds` 
            ON `b`.`repo_id` = `latest_builds`.`repo_id` AND `b`.`timestamp` = `latest_builds`.`timestamp`;
        ''', row_type=Sizes)
        assert r is not None
        return r
    
    def list_builds(
            self, 
            offset:int=0, 
            limit:int=10, 
            status: str='', 
            user: str='',
            repo_id: str = ''
        ) -> list[BuildActivity]:
        if offset < 0: offset = 0
        if limit < 0: limit = 0
        if not status in ['p', 's', 'v', 'f', '']: status = ''
        return self._fetch_all('''
            SELECT `b`.`id`, `b`.`repo_id`, `u`.`id` AS `user_id`, `u`.`login` AS `user_login`, `b`.`status`, `b`.`timestamp`, `b`.`size`
            FROM `builds` AS `b`
            JOIN `users` AS `u` ON `b`.`user_id` = `u`.`id`
            WHERE `b`.`repo_id` LIKE ?
            AND `b`.`status` LIKE ?
            AND `u`.`login` LIKE ?
            ORDER BY `b`.`timestamp` DESC
            LIMIT ?, ?;
        ''', (repo_id or '%', status or '%', user or '%', offset, limit), row_type=BuildActivity)
    
    def expire_user_builds(self, user_id: int) -> None:
        # Removes non-latest builds
        self._cursor().execute('''
            DELETE FROM `builds`
            WHERE `id` in (
                SELECT `b`.`id` 
                FROM `builds` AS `b`
                LEFT JOIN `repos` AS `r` ON `r`.`id` = `b`.`repo_id`
                WHERE `b`.`user_id` = ? 
                AND (
                    -- orphaned build
                    `r`.`id` is NULL
                    OR
                    -- not latest build for repo
                    `b`.`id` != (
                        SELECT `id` FROM `builds` AS `b2`
                        WHERE `b2`.`repo_id` = `b`.`repo_id`
                        ORDER BY `b2`.`timestamp` DESC, `b2`.`id`
                        LIMIT 1
                    )
                )
            );
        ''', [user_id])
        # Sets all remaining builds as expired
        self._cursor().execute('UPDATE `builds` SET `timestamp` = 0 WHERE `user_id` = ?;', [user_id])
        self._commit()