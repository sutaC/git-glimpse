"""Module provides interface for database usage."""
from src.lib.database_rows import Build, BuildActivity, BuildWork, Limits, Repo, RepoActivity, RepoClone, RepoRow, RepoSelect, RoleType, RowType, Session, Sizes, TokenCreate, User, UserActivity, UserAuth, UserBan, UserNotificationsData, UserRecover, UserTs, Views
from src.lib.utils import is_vaild_status
from secrets import token_urlsafe
from typing import Literal
from pathlib import Path
from src.lib import auth
from time import time
from flask import g
import sqlite3
import os

class Database:
    """Database handling class.
    
    When raw mode flag is True database will **not** use Flask request safe g namespace for connection.

    Args:
        path: Path to database file.
        raw_mode: Raw mode flag (default False.)
    """

    def __init__(self, path: Path, raw_mode:bool=False) -> None:
        self.path: Path = path
        self._raw_mode: bool = raw_mode
        self._raw_conn: sqlite3.Connection | None = None

    # --- helpers
    def init_db(self) -> None:
        """Initializes database file."""
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
                `created` INTEGER NOT NULL DEFAULT (unixepoch()),
                `last_login` INTERGER NON NULL DEFAULT(unixepoch()),
                `inactive` INTEGER NOT NULL DEFAULT 0 CHECK (`inactive` IN (0, 1)),
                `notifications` INTEGER NOT NULL DEFAULT 0 CHECK (`notifications` IN (0, 1))
            );
            CREATE INDEX IF NOT EXISTS `idx_users_login` ON `users`(`login`);
            CREATE INDEX IF NOT EXISTS `idx_users_notifications` ON `users`(`notifications`);
            CREATE INDEX IF NOT EXISTS `idx_users_inactive_last_login` ON `users`(`inactive`, `last_login`);
            -- user_bans
            CREATE TABLE IF NOT EXISTS `user_bans` (
                `id` INTEGER PRIMARY KEY,
                `user_id` INTEGER UNIQUE REFERENCES `users`(`id`) ON DELETE CASCADE,
                `banned_at` INTEGER NOT NULL DEFAULT (unixepoch()),
                `banned_by` INTEGER REFERENCES `users`(`id`) ON DELETE SET NULL,
                `ban_reason` TEXT
            );
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
                `hidden` INTEGER NOT NULL DEFAULT 0 CHECK (`hidden` IN (0, 1)),
                UNIQUE(`user_id`, `url`)
            );
            CREATE INDEX IF NOT EXISTS `idx_repos_user_id` ON `repos`(`user_id`);
            -- builds
            CREATE TABLE IF NOT EXISTS `builds` (
                `id` INTEGER PRIMARY KEY,
                `user_id` TEXT NOT NULL REFERENCES `users`(`id`) ON DELETE CASCADE,
                `repo_id` TEXT REFERENCES `repos`(`id`) ON DELETE SET NULL,
                `status` TEXT NOT NULL DEFAULT 'p' CHECK (`status` IN ('s', 'p', 'f', 'v', 'r')), 
                `timestamp` INTEGER NOT NULL DEFAULT (unixepoch()),
                `size` INTEGER CHECK (`size` >= 0),
                `archive_size` INTEGER CHECK (`archive_size` >= 0),
                `code` TEXT
            );
            CREATE INDEX IF NOT EXISTS `idx_builds_user_time` ON builds(`user_id`, `timestamp` DESC);
            CREATE INDEX IF NOT EXISTS `idx_builds_repo_time` ON builds(`repo_id`, `timestamp` DESC);
            -- tokens
            CREATE TABLE IF NOT EXISTS `tokens` (
                `id` TEXT PRIMARY KEY,
                `user_id` TEXT NOT NULL REFERENCES `users`(`id`) ON DELETE CASCADE,
                `type` TEXT NOT NULL CHECK (`type` IN ('e_ver', 'p_rec')),
                `issued` INTEGER NOT NULL DEFAULT (unixepoch()),
                `expires` INTEGER NOT NULL DEFAULT (unixepoch() + 3600)
            );
            CREATE INDEX IF NOT EXISTS `idx_tokens_user_type` ON tokens(`user_id`, `type`);
            CREATE INDEX IF NOT EXISTS `idx_tokens_type_expires` ON tokens(`type`, `expires`);
            -- repo_views
            CREATE TABLE IF NOT EXISTS `repo_views` (
                `visitor_hash` TEXT NOT NULL,
                `repo_id` TEXT NOT NULL REFERENCES `repos`(`id`) ON DELETE CASCADE,
                `day` INTEGER NOT NULL CHECK (`day` > 0),
                `first_view` INTEGER NOT NULL DEFAULT (unixepoch()),
                `location` TEXT CHECK (length(`location`) = 2),
                `client` TEXT CHECK (`client` IN (
                    'chrome', 'chrome_mobile', 'firefox', 'firefox_mobile',
                    'safari', 'edge', 'opera', 'bot', 'unknown'
                )), 
                PRIMARY KEY (`repo_id`, `visitor_hash`, `day`)
            );
            CREATE INDEX IF NOT EXISTS `idx_repo_views_repo_day` ON `repo_views`(`repo_id`, `day`);
        ''')
        self._commit()
        cursor.execute("SELECT `id` FROM `users` WHERE `login` = 'root';")
        root_id = cursor.fetchone()
        if not root_id:
            password = os.getenv("ROOT_PASSWORD") or "password"
            hashed_password = auth.hash_password(password)
            self._connect().execute("PRAGMA foreign_keys = OFF")
            root_id = self.add_user("root", "", hashed_password, 'a')
            self._connect().execute("PRAGMA foreign_keys = ON")
            self.set_user_verified(root_id)
        self.path.chmod(0o600)

    def _connect(self) -> sqlite3.Connection:
        """Gives database connection.

        Returns:
            Databse connection.
        """
        if self._raw_mode:
            if self._raw_conn is None:
                self._raw_conn = sqlite3.connect(self.path)
                self._raw_conn.row_factory = sqlite3.Row
                self._raw_conn.execute("PRAGMA foreign_keys = ON")
            return self._raw_conn
        else:
            if "db" not in g:
                g.db = sqlite3.connect(self.path)
                g.db.row_factory = sqlite3.Row
                g.db.execute("PRAGMA foreign_keys = ON")
            return g.db

    def _commit(self) -> None:
        """Commits to database."""
        self._connect().commit()

    def _cursor(self) -> sqlite3.Cursor:
        """Gives database cursor.
        
        Retruns:
            Database cursor.
        """
        return self._connect().cursor()

    def _fetch_one(self, sql: str, params: tuple = (), row_type: type[RowType] = dict) -> RowType | None:
        """Fetches one row from database.
        
        Args:
            sql: SQL query.
            params: Params used in query.
            row_type: Type of returned row (default dict).

        Returns:
            One databse row selected by query. 
        """
        row = self._cursor().execute(sql, params).fetchone()
        return row_type(*row) if row else None

    def _fetch_all(self, sql: str, params: tuple = (), row_type: type[RowType] = dict) -> list[RowType]:
        """Fetches all rows from database.
        
        Args:
            sql: SQL query.
            params: Params used in query.
            row_type: Type of returned rows (default dict).

        Returns:
            All databse rows selected by query.
        """
        rows = self._cursor().execute(sql, params).fetchall()
        return [row_type(*row) for row in rows]

    def _fetch_value(self, sql: str, params: tuple = ()):
        """Fetches one value from database.
        
        Args:
            sql: SQL query.
            params: Params used in query.

        Returns:
            Single value selected by query. 
        """
        row = self._cursor().execute(sql, params).fetchone()
        return row[0] if row else None

    def _fetch_count(self, query: str, params: tuple = ()) -> int:
        """Fetches count value from database.
        
        Args:
            sql: SQL query.
            params: Params used in query.

        Returns:
            Single count value selected by query. 
        """
        row = self._cursor().execute(query, params).fetchone()
        return row[0] if row else 0

    def _fetch_exists(self, query: str, params: tuple = ()) -> bool:
        """Fetches if selected data is in database.
        
        Args:
            sql: SQL query.
            params: Params used in query.

        Returns:
            True if selected data exists.
        """
        row = self._cursor().execute(query, params).fetchone()
        return bool(row)

    def _close(self) -> None:
        """Closes database connection."""
        if self._raw_mode:
            if self._raw_conn is not None:
                self._raw_conn.close()
                self._raw_conn = None
        else:
            db = g.pop("db", None)
            if db: db.close()

    # --- repos
    def add_repo(self, user_id: int, url: str, repo_name: str, ssh_key: str | None = None) -> str:
        """Create a new repo.
        
        Args:
            user_id: Id of owner user.
            url: Repo URL.
            repo_name: Name of repo.
            ssh_key: Encrypted SSH key text.
        
        Retruns:
            New repos id.
        """
        repo_id = token_urlsafe(16)
        self._cursor().execute(
            'INSERT INTO `repos` (`id`, `user_id`, `url`, `repo_name`, `ssh_key`) VALUES (?, ?, ?, ?, ?);', 
            (repo_id, user_id, url, repo_name, ssh_key)
        )
        self._commit()
        return repo_id

    def list_user_repos(self, user_id: int) -> list[RepoRow]:
        """Retrieve all repos from owner user.

        Args:
            user_id: Id of owner user.
        
        Returns:
            List of the RepoRow interface.
        """
        return self._fetch_all('''
            SELECT `repos`.`id`, `repos`.`repo_name` 
            FROM `users` 
            JOIN `repos` ON  `users`.`id` = `repos`.`user_id`
            WHERE `users`.`id` = ?;
        ''', (user_id,), RepoRow
        )

    def list_repos(
            self, 
            offset: int = 0, 
            limit: int = 10,
            status: str ='', 
            user: str = '',
            repo: str = '',
            url: str = '',
            key: str = '',
            hidden: str = ''
        ) -> list[RepoActivity]:
        """Retrieve all repos using filters.

        If filter is not specified (or an empty string) then it will skipped.   

        Args:
            offset: Amount rows to skip (default 0).
            limit: Limit of rows to return (default 10).
            status: Last build repo status.
            user: Repo owner user login.
            repo: Repo id.
            url: Repo URL.
            key: If repo has key ('1' or '0').
            hidden: If repo is hidden ('1' or '0').
        
        Returns:
            List of the RepoActivity interfaces.
        """
        if offset < 0: offset = 0
        if limit < 0: limit = 0
        if not is_vaild_status(status): status = ''
        if not key in ['1', '0', '']: key = ''
        if not hidden in ['1', '0', '']: hidden = ''
        return self._fetch_all('''
            SELECT  `r`.`id`, `u`.`id`, `u`.`login`, `r`.`url`, (`r`.`ssh_key` IS NOT NULL) AS `has_key`, `r`.`created`,
                    `lb`.`status`, `lb`.`size`, `lb`.`timestamp`, `r`.`hidden`         
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
            AND `hidden` LIKE ?
            ORDER BY `lb`.`timestamp` DESC
            LIMIT ?, ?;
        ''', (repo or '%', status or '%', user or '%', url or '%', key or '%', hidden or '%', offset, limit), 
        row_type=RepoActivity
    )

    def get_repo_select(self, repo_id: str) -> RepoSelect | None:
        """Retrieve repo select data.

        Args:
            repo_id: Repo id.

        Returns:
            The RepoSelect interface if found, otherwise None.
        """
        return self._fetch_one('SELECT `repo_name`, `hidden` FROM `repos` WHERE `id` = ?;', (repo_id,), RepoSelect)
    
    def get_repo_user_id(self, repo_id: str) -> int | None:
        """Retrieve repos owner user id.

        Args:
            repo_id: Repo id.

        Returns:
            Repos owner id if found, otherwise None.
        """
        return self._fetch_value('SELECT `user_id` FROM `repos` WHERE `id` = ?;', (repo_id,))

    def get_repo_for_clone(self, repo_id: str) -> RepoClone | None:
        """Retrieve repo clone data.

        Args:
            repo_id: Repo id.

        Returns:
            The RepoClone interface if found, otherwise None.
        """
        return self._fetch_one('SELECT `user_id`, `url`, `ssh_key` FROM `repos` WHERE `id` = ?;', (repo_id,), RepoClone)
    
    def get_repo(self, repo_id: str) -> Repo | None:
        """Retrieve repo data.

        Args:
            repo_id: Repo id.

        Returns:
            The Repo interface if found, otherwise None.
        """
        return self._fetch_one('SELECT `repo_name`, `url`, `user_id`, `created`, `hidden` FROM `repos` WHERE `id` = ?;', (repo_id,), Repo)
    
    def set_repo_hidden(self, repo_id: str, hidden: bool) -> None:
        """Set repo hidden flag.

        Args:
            repo_id: Repo id.
            hidden: Hidden flag to be set.
        """
        self._cursor().execute('UPDATE `repos` SET `hidden` = ? WHERE `id` = ?;', ((1 if hidden else 0), repo_id))
        self._commit()

    def is_repo_url_for_user(self, url: str, user_id: int) -> bool:
        """Check if user has repo url.

        Args:
            url: Repo url to find.
            user_id: User id.

        Returns:
            True if user has repo url.
        """
        return self._fetch_exists('SELECT 1 FROM `repos` WHERE `url` = ? AND `user_id` = ?;', (url, user_id))

    def count_user_repos(self, user_id: int) -> int:
        """Count user repos
        
        Args:
            user_id: User id.

        Returns:
            Count of user repos.
        """
        return self._fetch_count('SELECT COUNT(*) FROM `repos` WHERE `user_id` = ?;', (user_id,))

    def delete_repo(self, repo_id: str) -> None:
        """Delete repo
        
        Args:
            repo_id: Repo id.
        """
        self._cursor().execute('DELETE FROM `repos` WHERE `id` = ?;', (repo_id,))
        self._commit()

    def count_repos(self) -> int:
        """Count all repos
        
        Returns:
            Count all repos.
        """
        return self._fetch_count('SELECT COUNT(*) FROM `repos`;')
    
    def is_repo_owner_banned(self, repo_id: str) -> bool:
        """Check if repo owner user is banned.

        Args:
            repo_id: Repo id.

        Returns:
            True if repo owner user is banned.
        """
        return self._fetch_exists('''
            SELECT 1 
            FROM `user_bans`
            WHERE `user_id` = (SELECT `user_id` FROM `repos` WHERE `id` = ?);
        ''', (repo_id,))

    # --- users
    def add_user(self, login: str, email: str, password: str, role: RoleType = 'u') -> int:
        """Create a new user.
        
        Args:
            login: User login (uniqe).
            email: User email (uniqe).
            password: User password (hashed).
            role: User role code (default 'u').

        Returns:
            New user id.
        """
        cursor = self._cursor()
        cursor.execute('INSERT INTO `users` (`login`, `email`, `password`, `role`) VALUES (?, ?, ?, ?);', 
            (login, email, password, role)
        )
        self._commit()
        user_id = cursor.lastrowid
        assert isinstance(user_id, int)
        return user_id

    def set_user_verified(self, user_id: int, verified: bool = True) -> None:
        """Set user verified flag.
        
        Args:
            user_id: User id.
            verified: Verified flag to be set.
        """
        self._cursor().execute(
            'UPDATE `users` SET `is_verified` = ? WHERE `id` = ?;',
            ((1 if verified else 0), user_id)
        )
        self._commit()

    def unban_user(self, user_id: int) -> None:
        """Remove user ban.
        
        Args:
            user_id: User id.
        """
        self._cursor().execute(
            'DELETE FROM `user_bans` WHERE `user_id` = ?;',
            (user_id,)
        )
        self._commit()

    def ban_user(self, user_id: int, admin_id: int, ban_reason: str | None) -> None:
        """Create user ban.
        
        Args:
            user_id: User id.
            admin_id: Banning admin user id.
            ban_reason: Ban reason.
        """
        self._cursor().execute(
            'INSERT INTO `user_bans` (`user_id`, `banned_by`, `ban_reason`) VALUES (?, ?, ?);',
            (user_id, admin_id, ban_reason)
        )
        self._commit()

    def set_user_role(self, user_id: int, role: RoleType = 'u') -> None:
        """Set user role.
        
        Args:
            user_id: User id.
            role: User role code to be set.
        """
        assert role in ['a', 'u']
        self._cursor().execute(
            'UPDATE `users` SET `role` = ? WHERE `id` = ?;',
            (role, user_id)
        )
        self._commit()

    def set_user_password(self, user_id: int, password: str) -> None:
        """Set user password.
        
        Args:
            user_id: User id.
            password: Password to be set (hashed).
        """
        self._cursor().execute(
            'UPDATE `users` SET `password` = ? WHERE `id` = ?;',
            (password, user_id)
        )
        self._commit()

    def is_user_login(self, login: str) -> bool:
        """Check if user login in taken.
        
        Args:
            login: User login.

        Retruns:
            True if user login in taken.
        """
        return self._fetch_exists('SELECT 1 FROM `users` WHERE `login` = ?;', (login,))
    
    def is_user_verified(self, user_id: int) -> bool:
        """Check if user is verified.
        
        Args:
            user_id: User id.

        Retruns:
            True if user is verified.
        """
        r = self._fetch_value('SELECT `is_verified` FROM `users` WHERE `id` = ?;', (user_id,))
        return r is not None and bool(r)

    def is_user_email(self, email: str) -> bool:
        """Check if user email is taken.
        
        Args:
            email: User email.

        Retruns:
            True if user email is taken.
        """
        return self._fetch_exists('SELECT 1 FROM `users` WHERE `email` = ?;', (email,))

    def get_user_auth(self, login: str) -> UserAuth | None:
        """Retrieve user auth data by login.
        
        Args:
            login: User login.

        Retruns:
            The interface UserAuth if found, otherwise None. 
        """
        return self._fetch_one('SELECT `id`, `password`, `role` FROM `users` WHERE `login` = ?;', (login,), UserAuth)
    
    def get_user_login(self, user_id: int) -> str | None:
        """Retrieve user login by id.
        
        Args:
            user_id: User id.

        Retruns:
            User login if found, otherwise None. 
        """
        return self._fetch_value('SELECT `login` FROM `users` WHERE `id` = ?;', (user_id,))

    def get_user(self, user_id: int) -> User | None:
        """Retrieve user data.
        
        Args:
            user_id: User id.

        Retruns:
            The interface User if found, otherwise None. 
        """
        return self._fetch_one('''
            SELECT `u`.`login`, `u`.`role`, `u`.`is_verified`, `u`.`inactive`,
                    (SELECT 1 FROM `user_bans` WHERE `user_id` = `u`.`id`) AS `is_banned`
            FROM `users` AS `u`
            WHERE `u`.`id` = ?;
        ''', (user_id,), User)

    def get_user_ban(self, user_id: int) -> UserBan | None:
        """Retrieve user ban data.
        
        Args:
            user_id: User id.

        Retruns:
            The interface UserBan if found, otherwise None. 
        """
        return self._fetch_one('''
            SELECT `u`.`login` AS `banned_by_login`, `b`.`banned_at`, `b`.`ban_reason`
            FROM `user_bans` AS `b`
            LEFT JOIN `users` AS `u` ON `b`.`banned_by` = `u`.`id`
            WHERE `b`.`user_id` = ?;
        ''', (user_id,), UserBan)

    def get_user_ts(self, user_id: int) -> UserTs | None:
        """Retrieve user timestamp data.
        
        Args:
            user_id: User id.

        Retruns:
            The interface UserTs if found, otherwise None. 
        """
        return self._fetch_one('SELECT `created`, `last_login` FROM `users` WHERE `id` = ?;', (user_id,), UserTs)

    def get_user_by_email(self, email: str) -> UserRecover | None:
        """Retrieve user recover data by email.
        
        Args:
            email: User email.

        Retruns:
            The interface UserRecover if found, otherwise None. 
        """
        if not email: return None
        return self._fetch_one('SELECT `id`, `login`, `is_verified` FROM `users` WHERE `email` = ?;', (email,), UserRecover)

    def delete_user(self, user_id: int) -> None:
        """Delete user.
        
        Args:
            user_id: User id.
        """
        self._cursor().execute('DELETE FROM `users` WHERE `id` = ?;', (user_id,))
        self._commit()
    
    def get_user_email(self, user_id: int) -> str | None:
        """Retrieve user email.
        
        Args:
            user_id: User id.

        Retruns:
            User email if found, otherwise None. 
        """
        return self._fetch_value('SELECT `email` FROM `users` WHERE `id` = ?;', (user_id,)) 
    
    def get_user_notifications(self, user_id: int) -> bool:
        """Retrieve user notifications preference.
        
        Args:
            user_id: User id.

        Retruns:
            User notifications preference. 
        """
        return bool(self._fetch_value('SELECT `notifications` FROM `users` WHERE `id` = ?;', (user_id,)))


    def set_user_notifications(self, user_id: int, notifications: bool) -> None:
        """Sets user notifications preference.
        
        Args:
            user_id: User id.
            notifications: User notifications preference
        """
        self._cursor().execute('UPDATE `users` SET `notifications` = ? WHERE `id` = ?;', (notifications, user_id))
        self._commit()

    def get_user_limits(self, user_id: int) -> Limits | None:
        """Retrieve user limits data.
        
        Args:
            user_id: User id.

        Retruns:
            The interface Limits if found, otherwise None. 
        """
        return self._fetch_one('''
            SELECT `roles`.`builds_user_limit`, `roles`.`repo_limit` 
            FROM `users` JOIN `roles` ON `users`.`role` = `roles`.`id` 
            WHERE `users`.`id` = ?;
        ''', (user_id,), Limits)

    def count_users(self) -> int:
        """Count all users data.
        
        Retruns:
            Count of all users. 
        """
        return self._fetch_count('SELECT COUNT(*) FROM `users`;')

    def list_users(
        self, 
        offset: int = 0, 
        limit: int = 10,
        login: str = '',
        email: str = '',
        role: str = '',
        is_verified: str = '',
        is_banned: str = '',
        inactive: str = ''
    ) -> list[UserActivity]:
        """Retrieve all users using filters.

        If filter is not specified (or an empty string) then it will skipped.   

        Args:
            offset: Amount rows to skip (default 0).
            limit: Limit of rows to return (default 10).
            login: User login.
            email: User email.
            role: User role code.
            is_verified: If user is verified ('1' or '0').
            is_banned: If user is banned ('1' or '0').
            inactive: If user is inavtive ('1' or '0').
        
        Returns:
            List of the RepoActivity interfaces.
        """
        if role not in ['a', 'u', '']: role = '' 
        if is_verified not in ['1', '0', '']: is_verified = '' 
        if is_banned not in ['1', '0', '']: is_banned = '' 
        if inactive not in ['1', '0', '']: inactive = '' 
        return self._fetch_all(f'''
            SELECT  `u`.`id`, `u`.`login`, `u`.`email`, `u`.`is_verified`, 
                    (SELECT 1 FROM `user_bans` WHERE `user_id` = `u`.`id`) AS `is_banned`, 
                    `u`.`role`, `u`.`created`, `u`.`inactive`
            FROM `users` AS `u`
            WHERE `u`.`login` LIKE ?
            AND `u`.`email` LIKE ?
            AND `u`.`is_verified` LIKE ?
            AND `u`.`role` LIKE ?
            AND `u`.`inactive` LIKE ?
            {f'AND {'NOT' if is_banned == '0' else ''} `is_banned`' if is_banned else ''} 
            ORDER BY `u`.`created` DESC
            LIMIT ?, ?;
        ''', (login or '%', email or '%', is_verified or '%', role or '%', inactive or '%', offset, limit), 
            row_type=UserActivity
        )

    def update_last_user_login(self, user_id: int) -> None:
        """Sets user last login timestamp to current timestamps.
        
        Args:
            user_id: User id.
        """
        self._cursor().execute('UPDATE `users` SET `last_login` = unixepoch(), `inactive` = 0 WHERE `id` = ?;', (user_id,))
        self._commit()

    def list_user_notifications_data(self) -> list[UserNotificationsData]:
        """Retrieve all user notifications data.
        
        Returns:
            List of user notifications data.
        """
        return self._fetch_all('''
            SELECT `u`.`id`, `u`.`login`, `u`.`email`, COUNT(DISTINCT `rv`.`visitor_hash`) AS `views`
            FROM `users` AS `u`
            JOIN `repos` AS `r` ON `u`.`id` = `r`.`user_id`
            JOIN `repo_views` AS `rv` ON `r`.`id` = `rv`.`repo_id` 
            WHERE `u`.`is_verified` = 1
                AND `u`.`notifications` = 1
                AND `rv`.`first_view` > (unixepoch() - 86400) -- last 24h
            GROUP BY `u`.`id`
            HAVING `views` > 0;
        ''', row_type=UserNotificationsData)

    # --- sessions
    def add_session(self, user_id: int, expires: int) -> str:
        """Create a new session.
        
        Args:
            user_id: User id.
            expires: Timestamp of session expiriation.

        Retruns:
            New sessions id.
        """
        id = token_urlsafe(32)
        self._cursor().execute('INSERT INTO `sessions` (`id`, `user_id`, `expires`) VALUES (?, ?, ?);', (id, user_id, expires))
        self._commit()
        return id
    
    def get_session(self, session_id: str) -> Session | None:
        """Retrieve session data.
        
        Args:
            session_id: Session id.

        Retruns:
            The interface Session if found, otherwise None. 
        """
        return self._fetch_one('SELECT `user_id`, `expires` FROM `sessions` WHERE `id` = ?;', (session_id,), Session)
    
    def delete_session(self, session_id: str) -> None:
        """Delete session.
        
        Args:
            session_id: Session id.
        """
        self._cursor().execute('DELETE FROM `sessions` WHERE `id` = ?;', (session_id,))
        self._commit()

    def delete_user_sessions(self, user_id: int) -> None:
        """Delete all users sessions.
        
        Args:
            user_id: User id.
        """
        self._cursor().execute('DELETE FROM `sessions` WHERE `user_id` = ?;', (user_id,))
        self._commit()

    def delete_all_expired_sessions(self) -> None:
        """Delete all expired sessions."""
        self._cursor().execute('DELETE FROM `sessions` WHERE `expires` < unixepoch();')
        self._commit()

    def delete_user_expired_sessions(self, user_id: int) -> None:
        """Delete all users expired sessions.
        
        Args:
            user_id: User id.
        """
        self._cursor().execute('DELETE FROM `sessions` WHERE `user_id` = ? AND `expires` < unixepoch();', (user_id,))
        self._commit()        

    # --- builds
    def add_build(self, user_id: int, repo_id: str) -> int:
        """Create a new build with `pending` status.
        
        Args:
            user_id: User id.
            repo_id: Repo id.

        Retruns:
            New builds id.
        """
        cursor = self._cursor()
        cursor.execute('INSERT INTO `builds` (`user_id`, `repo_id`) VALUES (?, ?);', (user_id, repo_id))
        self._commit()
        build_id = cursor.lastrowid
        assert isinstance(build_id, int)
        return build_id
    
    def update_build(self, build_id: int, status: str, size: int | None = None, archive_size:  int | None = None, code: str | None = None) -> None:
        """Update build.
        
        Args:
            build_id: Build id.
            status: Build status to be set.
            size: Build total size to be set.
            archive_size: Build archive size to be set.
            code: Build error code to be set.
        """
        self._cursor().execute('''
            UPDATE `builds` SET `status` = ?, `size` = ?, `archive_size` = ?, `code` = ? WHERE `id` = ?;
        ''', (status, size, archive_size, code, build_id))
        self._commit()

    def fail_all_user_pending_builds(self, user_id: int) -> None:
        """Set all user builds as `failed`.
        
        Args:
            user_id: User id.
        """
        self._cursor().execute('''
            UPDATE `builds` SET `status` = 'f' WHERE `status` = 'p' AND `user_id` = ?;
        ''', (user_id,))
        self._commit()

    def has_repo_active_build(self, repo_id: str) -> bool:
        """Check if repo has build with `pending` or `running` status.
        
        Args:
            repo_id: Repo id.

        Returns:
            True if repo has active build.
        """
        return self._fetch_exists("SELECT 1 FROM `builds` WHERE `status` IN ('p', 'r') AND `repo_id` = ? LIMIT 1;", (repo_id,))

    def get_latest_build(self, repo_id: str) -> Build | None:
        """Retrieve latest repos build data.
        
        Args:
            repo_id: Repo id.

        Retruns:
            The interface Build if found, otherwise None. 
        """
        return self._fetch_one(
            'SELECT `status`, `timestamp`, `size`, `code` FROM `builds` WHERE `repo_id` = ? ORDER BY `timestamp` DESC LIMIT 1;', 
            (repo_id,), Build
        )
    
    def count_user_builds(self, user_id: int) -> int:
        """Count user builds in last 7 days.
        
        Args:
            user_id: User id.

        Retruns:
            Count of user builds. 
        """
        return self._fetch_count('''
            SELECT COUNT(*) FROM `builds` 
            WHERE `user_id` = ? AND `builds`.`timestamp` > unixepoch() - 7*24*3600;
        ''', (user_id,)
        )
    
    def count_last24h_builds(self) -> int:
        """Count builds in last 24h.

        Retruns:
            Count of builds. 
        """
        return self._fetch_count('SELECT COUNT(*) FROM `builds` WHERE `timestamp` > unixepoch() - 24*3600')
    
    def count_last7d_builds(self) -> int:
        """Count builds in last 7 days.

        Retruns:
            Count of builds. 
        """
        return self._fetch_count('SELECT COUNT(*) FROM `builds` WHERE `timestamp` > unixepoch() - 7*24*3600')

    def sum_build_sizes(self) -> Sizes:
        """Calculate sum of all build sizes.

        Retruns:
            Sum of all build sizes. 
        """
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
            offset: int = 0, 
            limit: int = 10, 
            status: str= '', 
            user: str= '',
            repo_id: str = '',
            code: str | None = None
        ) -> list[BuildActivity]:
        """Retrieve all builds using filters.

        If filter is not specified (or an empty string) then it will skipped.   

        Args:
            offset: Amount rows to skip (default 0).
            limit: Limit of rows to return (default 10).
            status: Build status.
            user: Build repo owner user login.
            repo_id: Build repo id.
            code: Build error code.
        
        Returns:
            List of the BuildActivity interfaces.
        """
        if offset < 0: offset = 0
        if limit < 0: limit = 0
        if not is_vaild_status(status): status = ''
        return self._fetch_all(f'''
            SELECT `b`.`id`, `b`.`repo_id`, `u`.`id` AS `user_id`, `u`.`login` AS `user_login`, `b`.`status`, `b`.`code`, `b`.`timestamp`, `b`.`size`
            FROM `builds` AS `b`
            JOIN `users` AS `u` ON `b`.`user_id` = `u`.`id`
            WHERE `b`.`repo_id` LIKE ?
            AND `b`.`status` LIKE ?
            AND `u`.`login` LIKE ?
            {'AND `b`.`code` LIKE ?' if code else 'AND ?'}
            ORDER BY `b`.`timestamp` DESC
            LIMIT ?, ?;
        ''', (repo_id or '%', status or '%', user or '%', code or 1, offset, limit), row_type=BuildActivity)
    
    def expire_user_builds(self, user_id: int) -> None:
        """Expire all user builds.
        
        Removes all non-latest builds of user and sets all remaining builds as expired.
        
        Args:
            user_id: User id.
        """
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

    def get_pending_build(self) -> BuildWork | None:
        """Retrieve oldest pening build work data.
        
        Returns:
            The BuildWork interface if found, otherwise None.
        """
        return self._fetch_one(
            "SELECT `id`, `repo_id` FROM `builds` WHERE `status` = 'p' ORDER BY `timestamp` ASC, `id` ASC LIMIT 1;",
            row_type=BuildWork
        )
    
    def resurect_running_builds(self) -> None:
        """Set status `pending` for all `running` builds."""
        self._cursor().execute("UPDATE `builds` SET `status` = 'p' WHERE `status` = 'r';")
    
    # --- tokens
    def add_token(self, user_id: int, type: Literal['e_ver', 'p_rec']) -> TokenCreate:
        """Create a new token.
        
        Token types:
        - e_ver = Email verification
        - p_rec = Password recovery

        Args:
            user_id: User id.
            type: Token type.
        
        Retruns:
            The interface TokenCreate.
        """
        assert type in ['e_ver', 'p_rec']
        tid = token_urlsafe(32)
        expires = int(time()) + 3600 # now + 1h
        self._cursor().execute('''
            INSERT INTO `tokens` (`id`, `user_id`, `type`, `expires`)
            VALUES (?, ?, ?, ?);
        ''', (tid, user_id, type, expires))
        self._commit()
        return TokenCreate(tid, expires)
    
    def has_recent_token(self, user_id: int, type: Literal['e_ver', 'p_rec']) -> bool:
        """Check if user has recen token.
        
        Recent token will be issued in last:
        - 10 minutes : password_recovery ('p_rec')
        - 10 minutes : email_verification ('e_ver')

        Token types:
        - e_ver = Email verification
        - p_rec = Password recovery

        Args:
            user_id: User id.
            type: Token type.
        
        Returns:
            True if user has recent token.
        """
        assert type in ['e_ver', 'p_rec']
        return self._fetch_exists('''
            SELECT 1 FROM `tokens` 
            WHERE `user_id` = ? 
            AND `type` = ?
            AND `issued` > (unixepoch() - 600)
        ''', (user_id, type))

    def is_valid_token(self, token: str, user_id: int, type: Literal['e_ver', 'p_rec']) -> bool:
        """Check if user token is valid.

        Token types:
        - e_ver = Email verification
        - p_rec = Password recovery

        Args:
            token: Token id.
            user_id: User id.
            type: Token type.
        
        Returns:
            True if user token is valid.
        """
        assert type in ['e_ver', 'p_rec']
        return self._fetch_exists('''
            SELECT 1 FROM `tokens` 
            WHERE `id` = ? 
            AND `user_id` = ? 
            AND `type` = ?
            AND `expires` > unixepoch()
        ''', (token, user_id, type))
    
    def get_valid_token_user(self, token: str, type: Literal['e_ver', 'p_rec']) -> int | None:
        """Retrieve user id by token if valid.

        Token types:
        - e_ver = Email verification
        - p_rec = Password recovery

        Args:
            token: Token id.
            type: Token type.
        
        Returns:
            User id if found, otherwise None.
        """
        assert type in ['e_ver', 'p_rec']
        return self._fetch_value('''
            SELECT `user_id` FROM `tokens`
            WHERE `id` = ? 
            AND `type` = ?
            AND `expires` > unixepoch()
        ''', (token, type))

    def delete_user_tokens(self, user_id: int, type: Literal['e_ver', 'p_rec']) -> None:
        """Delete all user tokens by type.

        Token types:
        - e_ver = Email verification
        - p_rec = Password recovery

        Args:
            user_id: User id.
            type: Token type.
        """
        assert type in ['e_ver', 'p_rec']
        self._cursor().execute('''
            DELETE FROM `tokens` 
            WHERE `user_id` = ? 
            AND `type` = ?
        ''', (user_id, type))
        self._commit()

    # --- repo_views
    def add_repo_view(self, repo_id: str, visitor_hash: str, client: str, location: str | None) -> bool:
        """Create a new repo view.
        
        Args:
            repo_id: Repo id.
            visitor_hash: Hash identifying visitor.
            client: Visitor cient type.
            location: Visitor location code.

        Retruns:
            True if view was added.
        """
        day = int(time() // 86400)
        c = self._cursor()
        c.execute('''
            INSERT OR IGNORE INTO `repo_views` 
                (`visitor_hash`, `repo_id`, `day`, `location`, `client`)
            VALUES (?, ?, ?, ?, ?);
        ''', (visitor_hash, repo_id, day, location, client))
        self._commit()
        return bool(c.rowcount)

    def count_repo_views(self, repo_id: str) -> int:
        """Count all repo views.
        
        Args:
            repo_id: Repo id.

        Retruns:
            Count of repo views.
        """
        return self._fetch_count('SELECT COUNT(*) FROM `repo_views` WHERE `repo_id` = ?;', (repo_id,))

    def list_user_repo_views(self, user_id: int, offset: int = 0, limit: int = 10) -> list[Views]:
        """Retrieve all users repo views using filters.
        Args:
            user_id: User id.
            offset: Amount rows to skip (default 0).
            limit: Limit of rows to return (default 10).
        
        Returns:
            List of the Views interfaces.
        """
        return self._fetch_all('''
            SELECT `rv`.`client`, `rv`.`location`, `r`.`repo_name`, `rv`.`first_view`
            FROM `users` AS `u`
            JOIN `repos` AS `r` ON `u`.`id` = `r`.`user_id`
            JOIN `repo_views` AS `rv` ON `r`.`id` = `rv`.`repo_id`
            WHERE `u`.`id` = ?
            ORDER BY `rv`.`first_view` DESC
            LIMIT ?, ?;
        ''', (user_id, offset, limit), Views)

    def count_user_repo_views(self, user_id: int) -> int:
        """Count all users repo views.
        
        Args:
            user_id: User id.

        Retruns:
            Count of users repo views.
        """
        return self._fetch_count('''
            SELECT COUNT(*)
            FROM `users` AS `u`
            JOIN `repos` AS `r` ON `u`.`id` = `r`.`user_id`
            JOIN `repo_views` AS `rv` ON `r`.`id` = `rv`.`repo_id`
            WHERE `u`.`id` = ?;
        ''', (user_id,))