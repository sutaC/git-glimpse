<a id="notifications_worker"></a>

# notifications\_worker

<a id="notifications_worker.send_notifications"></a>

#### send\_notifications

```python
def send_notifications() -> None
```

Send notifications to all relevant users.

<a id="build_worker"></a>

# build\_worker

<a id="wsgi"></a>

# wsgi

Entry point for wsgi server.

<a id="app"></a>

# app

<a id="app.static_file"></a>

#### static\_file

```python
def static_file(name: str) -> str
```

Gives URL for static file.

In `debug` mode it will serve regular files and in `prod` mode it will served build minified version for caching.
If file is not included in `static/dist/` the function will return regular path.

**Arguments**:

- `name` - Path to resource in static directory.
  

**Returns**:

  URL for resource.

<a id="cleanup_worker"></a>

# cleanup\_worker

<a id="cleanup_worker.get_last_cleanup"></a>

#### get\_last\_cleanup

```python
def get_last_cleanup() -> CleanupData | None
```

Gives last saved cleanup statistics.

**Returns**:

  The interface CleanupData if found, otherwise None.

<a id="cleanup_worker.run_cleanup"></a>

#### run\_cleanup

```python
def run_cleanup() -> None
```

Run full cleanup.

This function saves resulst in file stored in `data/`.

<a id="globals"></a>

# globals

Module provides global constants.

<a id="lib"></a>

# lib

<a id="lib.git"></a>

# lib.git

Module provides interface for handing git repositories.

<a id="lib.git.RepoError"></a>

## RepoError Objects

```python
class RepoError(RuntimeError)
```

Repository cloning error.

Types of RepoError:
- 'f' = failure
- 'v' = violation

**Arguments**:

- `type` - Type of error.
- `code` - Error code corresponding to `lib.logger.Code`.
- `args` - Additional error information.

<a id="lib.git.RepoLockError"></a>

## RepoLockError Objects

```python
class RepoLockError(RuntimeError)
```

Repository lock error.

<a id="lib.git.RepoLock"></a>

## RepoLock Objects

```python
class RepoLock()
```

Repository lock for asyncronus repo managment.

**Arguments**:

- `repo_path` - Path to repository.

<a id="lib.git.RepoLock.acquire"></a>

#### acquire

```python
def acquire(timeout: int = 10) -> None
```

Acquires lock.

**Arguments**:

- `timeout` - Timeout for aquiring repo lock in seconds (default 10).
  

**Raises**:

- `RepoLockError` - When repository lock could not be aquired.

<a id="lib.git.RepoLock.release"></a>

#### release

```python
def release() -> None
```

Releases repository lock.

<a id="lib.git.clone_repo"></a>

#### clone\_repo

```python
def clone_repo(url: str,
               repo_dir: Path,
               ssh_key: str | None = None) -> tuple[int, int]
```

Clones repository.

**Arguments**:

- `url` - Repository URL.
- `repo_dir` - Repository destination path (eg. `.../data/repos/[id]/`).
- `ssh_key` - Repository SSH key (only when using SSH URL).
  

**Returns**:

  Repository total size, repository artifact size.
  

**Raises**:

- `RepoError` - When clone fails unexpectedly or repository violates rules.

<a id="lib.git.remove_protected_dir"></a>

#### remove\_protected\_dir

```python
def remove_protected_dir(path: Path) -> None
```

Removes repository protected directories.

**Warning:** If this function operates on repository files you should be using `RepoLock`.

**Arguments**:

- `path` - Directory path to remove.

<a id="lib.git.remove_extracted_artifacts"></a>

#### remove\_extracted\_artifacts

```python
def remove_extracted_artifacts(repo_path: Path) -> bool
```

Removes extracted repository artifacts.

**Warning:** This function uses `RepoLock`.

**Arguments**:

- `repo_path` - Path to repository.
  

**Returns**:

  True if any one of extarcted artifacts was removed.
  

**Raises**:

- `RepoLockError` - If repository lock could not be acquired.

<a id="lib.git.get_repo_path"></a>

#### get\_repo\_path

```python
def get_repo_path(repo_path: Path, sub_path: Path) -> Path
```

Gives absolute path to repository resource.

**Arguments**:

- `repo_path` - Path to repository.
- `sub_path` - Inner repository path.
  

**Returns**:

  Absolute path to repository resource
  

**Raises**:

- `LookupError` - If resource is not found or path is invalid.

<a id="lib.git.zip_dir"></a>

#### zip\_dir

```python
def zip_dir(src_path: Path, dest_path: Path) -> str
```

Packs directory into zip archive.

**Warning:** If this function operates on repository files you should be using `RepoLock`.

**Arguments**:

- `src_path` - Source directory to pack.
- `dest_path` - Destination path where zip archive is written to.
  

**Returns**:

  Zip hash.

<a id="lib.git.get_total_repos_size"></a>

#### get\_total\_repos\_size

```python
def get_total_repos_size() -> int
```

Calculates total repositories size.

This function uses cache file stored in `data/` valid for 15 minutes.

**Returns**:

  Total size of all repositories.

<a id="lib.git.encrypt_ssh_key"></a>

#### encrypt\_ssh\_key

```python
def encrypt_ssh_key(ssh_key: str) -> str
```

Encrypts SSH key.

**Arguments**:

- `ssh_key` - SSH key to encrypt.
  

**Returns**:

  Encrypted SSH key.

<a id="lib.git.decrypt_ssh_key"></a>

#### decrypt\_ssh\_key

```python
def decrypt_ssh_key(ssh_key: str) -> str
```

Decrypts SSH key.

**Arguments**:

- `ssh_key` - SSH key to encrypt.
  

**Returns**:

  Decrypted SSH key.

<a id="lib.git.normalize_ssh_key"></a>

#### normalize\_ssh\_key

```python
def normalize_ssh_key(ssh_key: str) -> str
```

Normalizes SSH key.

**Arguments**:

- `ssh_key` - SSH key to normalize.
  

**Returns**:

  Normalized SSH key.

<a id="lib.git.validate_ssh_key"></a>

#### validate\_ssh\_key

```python
def validate_ssh_key(key: str) -> str | None
```

Validates SSH key.

**Arguments**:

- `key` - SSH key to validate (plain text).
  

**Returns**:

  None if valid otherwise str validation error.

<a id="lib.database"></a>

# lib.database

Module provides interface for database usage.

<a id="lib.database.Database"></a>

## Database Objects

```python
class Database()
```

Database handling class.

When raw mode flag is True database will **not** use Flask request safe g namespace for connection.

**Arguments**:

- `path` - Path to database file.
- `raw_mode` - Raw mode flag (default False.)

<a id="lib.database.Database.init_db"></a>

#### init\_db

```python
def init_db() -> None
```

Initializes database file.

<a id="lib.database.Database.add_repo"></a>

#### add\_repo

```python
def add_repo(user_id: int,
             url: str,
             repo_name: str,
             ssh_key: str | None = None) -> str
```

Create a new repo.

**Arguments**:

- `user_id` - Id of owner user.
- `url` - Repo URL.
- `repo_name` - Name of repo.
- `ssh_key` - Encrypted SSH key text.
  
  Retruns:
  New repos id.

<a id="lib.database.Database.list_user_repos"></a>

#### list\_user\_repos

```python
def list_user_repos(user_id: int) -> list[RepoRow]
```

Retrieve all repos from owner user.

**Arguments**:

- `user_id` - Id of owner user.
  

**Returns**:

  List of the RepoRow interface.

<a id="lib.database.Database.list_repos"></a>

#### list\_repos

```python
def list_repos(offset: int = 0,
               limit: int = 10,
               status: str = '',
               user: str = '',
               repo: str = '',
               url: str = '',
               key: str = '',
               hidden: str = '') -> list[RepoActivity]
```

Retrieve all repos using filters.

If filter is not specified (or an empty string) then it will skipped.

**Arguments**:

- `offset` - Amount rows to skip (default 0).
- `limit` - Limit of rows to return (default 10).
- `status` - Last build repo status.
- `user` - Repo owner user login.
- `repo` - Repo id.
- `url` - Repo URL.
- `key` - If repo has key ('1' or '0').
- `hidden` - If repo is hidden ('1' or '0').
  

**Returns**:

  List of the RepoActivity interfaces.

<a id="lib.database.Database.get_repo_select"></a>

#### get\_repo\_select

```python
def get_repo_select(repo_id: str) -> RepoSelect | None
```

Retrieve repo select data.

**Arguments**:

- `repo_id` - Repo id.
  

**Returns**:

  The RepoSelect interface if found, otherwise None.

<a id="lib.database.Database.get_repo_user_id"></a>

#### get\_repo\_user\_id

```python
def get_repo_user_id(repo_id: str) -> int | None
```

Retrieve repos owner user id.

**Arguments**:

- `repo_id` - Repo id.
  

**Returns**:

  Repos owner id if found, otherwise None.

<a id="lib.database.Database.get_repo_for_clone"></a>

#### get\_repo\_for\_clone

```python
def get_repo_for_clone(repo_id: str) -> RepoClone | None
```

Retrieve repo clone data.

**Arguments**:

- `repo_id` - Repo id.
  

**Returns**:

  The RepoClone interface if found, otherwise None.

<a id="lib.database.Database.get_repo"></a>

#### get\_repo

```python
def get_repo(repo_id: str) -> Repo | None
```

Retrieve repo data.

**Arguments**:

- `repo_id` - Repo id.
  

**Returns**:

  The Repo interface if found, otherwise None.

<a id="lib.database.Database.set_repo_hidden"></a>

#### set\_repo\_hidden

```python
def set_repo_hidden(repo_id: str, hidden: bool) -> None
```

Set repo hidden flag.

**Arguments**:

- `repo_id` - Repo id.
- `hidden` - Hidden flag to be set.

<a id="lib.database.Database.is_repo_url_for_user"></a>

#### is\_repo\_url\_for\_user

```python
def is_repo_url_for_user(url: str, user_id: int) -> bool
```

Check if user has repo url.

**Arguments**:

- `url` - Repo url to find.
- `user_id` - User id.
  

**Returns**:

  True if user has repo url.

<a id="lib.database.Database.count_user_repos"></a>

#### count\_user\_repos

```python
def count_user_repos(user_id: int) -> int
```

Count user repos

**Arguments**:

- `user_id` - User id.
  

**Returns**:

  Count of user repos.

<a id="lib.database.Database.delete_repo"></a>

#### delete\_repo

```python
def delete_repo(repo_id: str) -> None
```

Delete repo

**Arguments**:

- `repo_id` - Repo id.

<a id="lib.database.Database.count_repos"></a>

#### count\_repos

```python
def count_repos() -> int
```

Count all repos

**Returns**:

  Count all repos.

<a id="lib.database.Database.is_repo_owner_banned"></a>

#### is\_repo\_owner\_banned

```python
def is_repo_owner_banned(repo_id: str) -> bool
```

Check if repo owner user is banned.

**Arguments**:

- `repo_id` - Repo id.
  

**Returns**:

  True if repo owner user is banned.

<a id="lib.database.Database.add_user"></a>

#### add\_user

```python
def add_user(login: str,
             email: str,
             password: str,
             role: RoleType = 'u') -> int
```

Create a new user.

**Arguments**:

- `login` - User login (uniqe).
- `email` - User email (uniqe).
- `password` - User password (hashed).
- `role` - User role code (default 'u').
  

**Returns**:

  New user id.

<a id="lib.database.Database.set_user_verified"></a>

#### set\_user\_verified

```python
def set_user_verified(user_id: int, verified: bool = True) -> None
```

Set user verified flag.

**Arguments**:

- `user_id` - User id.
- `verified` - Verified flag to be set.

<a id="lib.database.Database.unban_user"></a>

#### unban\_user

```python
def unban_user(user_id: int) -> None
```

Remove user ban.

**Arguments**:

- `user_id` - User id.

<a id="lib.database.Database.ban_user"></a>

#### ban\_user

```python
def ban_user(user_id: int, admin_id: int, ban_reason: str | None) -> None
```

Create user ban.

**Arguments**:

- `user_id` - User id.
- `admin_id` - Banning admin user id.
- `ban_reason` - Ban reason.

<a id="lib.database.Database.set_user_role"></a>

#### set\_user\_role

```python
def set_user_role(user_id: int, role: RoleType = 'u') -> None
```

Set user role.

**Arguments**:

- `user_id` - User id.
- `role` - User role code to be set.

<a id="lib.database.Database.set_user_password"></a>

#### set\_user\_password

```python
def set_user_password(user_id: int, password: str) -> None
```

Set user password.

**Arguments**:

- `user_id` - User id.
- `password` - Password to be set (hashed).

<a id="lib.database.Database.is_user_login"></a>

#### is\_user\_login

```python
def is_user_login(login: str) -> bool
```

Check if user login in taken.

**Arguments**:

- `login` - User login.
  
  Retruns:
  True if user login in taken.

<a id="lib.database.Database.is_user_verified"></a>

#### is\_user\_verified

```python
def is_user_verified(user_id: int) -> bool
```

Check if user is verified.

**Arguments**:

- `user_id` - User id.
  
  Retruns:
  True if user is verified.

<a id="lib.database.Database.is_user_email"></a>

#### is\_user\_email

```python
def is_user_email(email: str) -> bool
```

Check if user email is taken.

**Arguments**:

- `email` - User email.
  
  Retruns:
  True if user email is taken.

<a id="lib.database.Database.get_user_auth"></a>

#### get\_user\_auth

```python
def get_user_auth(login: str) -> UserAuth | None
```

Retrieve user auth data by login.

**Arguments**:

- `login` - User login.
  
  Retruns:
  The interface UserAuth if found, otherwise None.

<a id="lib.database.Database.get_user_login"></a>

#### get\_user\_login

```python
def get_user_login(user_id: int) -> str | None
```

Retrieve user login by id.

**Arguments**:

- `user_id` - User id.
  
  Retruns:
  User login if found, otherwise None.

<a id="lib.database.Database.get_user"></a>

#### get\_user

```python
def get_user(user_id: int) -> User | None
```

Retrieve user data.

**Arguments**:

- `user_id` - User id.
  
  Retruns:
  The interface User if found, otherwise None.

<a id="lib.database.Database.get_user_ban"></a>

#### get\_user\_ban

```python
def get_user_ban(user_id: int) -> UserBan | None
```

Retrieve user ban data.

**Arguments**:

- `user_id` - User id.
  
  Retruns:
  The interface UserBan if found, otherwise None.

<a id="lib.database.Database.get_user_ts"></a>

#### get\_user\_ts

```python
def get_user_ts(user_id: int) -> UserTs | None
```

Retrieve user timestamp data.

**Arguments**:

- `user_id` - User id.
  
  Retruns:
  The interface UserTs if found, otherwise None.

<a id="lib.database.Database.get_user_by_email"></a>

#### get\_user\_by\_email

```python
def get_user_by_email(email: str) -> UserRecover | None
```

Retrieve user recover data by email.

**Arguments**:

- `email` - User email.
  
  Retruns:
  The interface UserRecover if found, otherwise None.

<a id="lib.database.Database.delete_user"></a>

#### delete\_user

```python
def delete_user(user_id: int) -> None
```

Delete user.

**Arguments**:

- `user_id` - User id.

<a id="lib.database.Database.get_user_email"></a>

#### get\_user\_email

```python
def get_user_email(user_id: int) -> str | None
```

Retrieve user email.

**Arguments**:

- `user_id` - User id.
  
  Retruns:
  User email if found, otherwise None.

<a id="lib.database.Database.get_user_notifications"></a>

#### get\_user\_notifications

```python
def get_user_notifications(user_id: int) -> bool
```

Retrieve user notifications preference.

**Arguments**:

- `user_id` - User id.
  
  Retruns:
  User notifications preference.

<a id="lib.database.Database.set_user_notifications"></a>

#### set\_user\_notifications

```python
def set_user_notifications(user_id: int, notifications: bool) -> None
```

Sets user notifications preference.

**Arguments**:

- `user_id` - User id.
- `notifications` - User notifications preference

<a id="lib.database.Database.get_user_limits"></a>

#### get\_user\_limits

```python
def get_user_limits(user_id: int) -> Limits | None
```

Retrieve user limits data.

**Arguments**:

- `user_id` - User id.
  
  Retruns:
  The interface Limits if found, otherwise None.

<a id="lib.database.Database.count_users"></a>

#### count\_users

```python
def count_users() -> int
```

Count all users data.

Retruns:
    Count of all users.

<a id="lib.database.Database.list_users"></a>

#### list\_users

```python
def list_users(offset: int = 0,
               limit: int = 10,
               login: str = '',
               email: str = '',
               role: str = '',
               is_verified: str = '',
               is_banned: str = '',
               inactive: str = '') -> list[UserActivity]
```

Retrieve all users using filters.

If filter is not specified (or an empty string) then it will skipped.

**Arguments**:

- `offset` - Amount rows to skip (default 0).
- `limit` - Limit of rows to return (default 10).
- `login` - User login.
- `email` - User email.
- `role` - User role code.
- `is_verified` - If user is verified ('1' or '0').
- `is_banned` - If user is banned ('1' or '0').
- `inactive` - If user is inavtive ('1' or '0').
  

**Returns**:

  List of the RepoActivity interfaces.

<a id="lib.database.Database.update_last_user_login"></a>

#### update\_last\_user\_login

```python
def update_last_user_login(user_id: int) -> None
```

Sets user last login timestamp to current timestamps.

**Arguments**:

- `user_id` - User id.

<a id="lib.database.Database.list_user_notifications_data"></a>

#### list\_user\_notifications\_data

```python
def list_user_notifications_data() -> list[UserNotificationsData]
```

Retrieve all user notifications data.

**Returns**:

  List of user notifications data.

<a id="lib.database.Database.add_session"></a>

#### add\_session

```python
def add_session(user_id: int, expires: int) -> str
```

Create a new session.

**Arguments**:

- `user_id` - User id.
- `expires` - Timestamp of session expiriation.
  
  Retruns:
  New sessions id.

<a id="lib.database.Database.get_session"></a>

#### get\_session

```python
def get_session(session_id: str) -> Session | None
```

Retrieve session data.

**Arguments**:

- `session_id` - Session id.
  
  Retruns:
  The interface Session if found, otherwise None.

<a id="lib.database.Database.delete_session"></a>

#### delete\_session

```python
def delete_session(session_id: str) -> None
```

Delete session.

**Arguments**:

- `session_id` - Session id.

<a id="lib.database.Database.delete_user_sessions"></a>

#### delete\_user\_sessions

```python
def delete_user_sessions(user_id: int) -> None
```

Delete all users sessions.

**Arguments**:

- `user_id` - User id.

<a id="lib.database.Database.delete_all_expired_sessions"></a>

#### delete\_all\_expired\_sessions

```python
def delete_all_expired_sessions() -> None
```

Delete all expired sessions.

<a id="lib.database.Database.delete_user_expired_sessions"></a>

#### delete\_user\_expired\_sessions

```python
def delete_user_expired_sessions(user_id: int) -> None
```

Delete all users expired sessions.

**Arguments**:

- `user_id` - User id.

<a id="lib.database.Database.add_build"></a>

#### add\_build

```python
def add_build(user_id: int, repo_id: str) -> int
```

Create a new build with `pending` status.

**Arguments**:

- `user_id` - User id.
- `repo_id` - Repo id.
  
  Retruns:
  New builds id.

<a id="lib.database.Database.update_build"></a>

#### update\_build

```python
def update_build(build_id: int,
                 status: str,
                 size: int | None = None,
                 archive_size: int | None = None,
                 code: str | None = None) -> None
```

Update build.

**Arguments**:

- `build_id` - Build id.
- `status` - Build status to be set.
- `size` - Build total size to be set.
- `archive_size` - Build archive size to be set.
- `code` - Build error code to be set.

<a id="lib.database.Database.fail_all_user_pending_builds"></a>

#### fail\_all\_user\_pending\_builds

```python
def fail_all_user_pending_builds(user_id: int) -> None
```

Set all user builds as `failed`.

**Arguments**:

- `user_id` - User id.

<a id="lib.database.Database.has_repo_active_build"></a>

#### has\_repo\_active\_build

```python
def has_repo_active_build(repo_id: str) -> bool
```

Check if repo has build with `pending` or `running` status.

**Arguments**:

- `repo_id` - Repo id.
  

**Returns**:

  True if repo has active build.

<a id="lib.database.Database.get_latest_build"></a>

#### get\_latest\_build

```python
def get_latest_build(repo_id: str) -> Build | None
```

Retrieve latest repos build data.

**Arguments**:

- `repo_id` - Repo id.
  
  Retruns:
  The interface Build if found, otherwise None.

<a id="lib.database.Database.count_user_builds"></a>

#### count\_user\_builds

```python
def count_user_builds(user_id: int) -> int
```

Count user builds in last 7 days.

**Arguments**:

- `user_id` - User id.
  
  Retruns:
  Count of user builds.

<a id="lib.database.Database.count_last24h_builds"></a>

#### count\_last24h\_builds

```python
def count_last24h_builds() -> int
```

Count builds in last 24h.

Retruns:
    Count of builds.

<a id="lib.database.Database.count_last7d_builds"></a>

#### count\_last7d\_builds

```python
def count_last7d_builds() -> int
```

Count builds in last 7 days.

Retruns:
    Count of builds.

<a id="lib.database.Database.sum_build_sizes"></a>

#### sum\_build\_sizes

```python
def sum_build_sizes() -> Sizes
```

Calculate sum of all build sizes.

Retruns:
    Sum of all build sizes.

<a id="lib.database.Database.list_builds"></a>

#### list\_builds

```python
def list_builds(offset: int = 0,
                limit: int = 10,
                status: str = '',
                user: str = '',
                repo_id: str = '',
                code: str | None = None) -> list[BuildActivity]
```

Retrieve all builds using filters.

If filter is not specified (or an empty string) then it will skipped.

**Arguments**:

- `offset` - Amount rows to skip (default 0).
- `limit` - Limit of rows to return (default 10).
- `status` - Build status.
- `user` - Build repo owner user login.
- `repo_id` - Build repo id.
- `code` - Build error code.
  

**Returns**:

  List of the BuildActivity interfaces.

<a id="lib.database.Database.expire_user_builds"></a>

#### expire\_user\_builds

```python
def expire_user_builds(user_id: int) -> None
```

Expire all user builds.

Removes all non-latest builds of user and sets all remaining builds as expired.

**Arguments**:

- `user_id` - User id.

<a id="lib.database.Database.get_pending_build"></a>

#### get\_pending\_build

```python
def get_pending_build() -> BuildWork | None
```

Retrieve oldest pening build work data.

**Returns**:

  The BuildWork interface if found, otherwise None.

<a id="lib.database.Database.resurect_running_builds"></a>

#### resurect\_running\_builds

```python
def resurect_running_builds() -> None
```

Set status `pending` for all `running` builds.

<a id="lib.database.Database.add_token"></a>

#### add\_token

```python
def add_token(user_id: int, type: Literal['e_ver', 'p_rec']) -> TokenCreate
```

Create a new token.

Token types:
- e_ver = Email verification
- p_rec = Password recovery

**Arguments**:

- `user_id` - User id.
- `type` - Token type.
  
  Retruns:
  The interface TokenCreate.

<a id="lib.database.Database.has_recent_token"></a>

#### has\_recent\_token

```python
def has_recent_token(user_id: int, type: Literal['e_ver', 'p_rec']) -> bool
```

Check if user has recen token.

Recent token will be issued in last:
- 10 minutes : password_recovery ('p_rec')
- 10 minutes : email_verification ('e_ver')

Token types:
- e_ver = Email verification
- p_rec = Password recovery

**Arguments**:

- `user_id` - User id.
- `type` - Token type.
  

**Returns**:

  True if user has recent token.

<a id="lib.database.Database.is_valid_token"></a>

#### is\_valid\_token

```python
def is_valid_token(token: str, user_id: int, type: Literal['e_ver',
                                                           'p_rec']) -> bool
```

Check if user token is valid.

Token types:
- e_ver = Email verification
- p_rec = Password recovery

**Arguments**:

- `token` - Token id.
- `user_id` - User id.
- `type` - Token type.
  

**Returns**:

  True if user token is valid.

<a id="lib.database.Database.get_valid_token_user"></a>

#### get\_valid\_token\_user

```python
def get_valid_token_user(token: str, type: Literal['e_ver',
                                                   'p_rec']) -> int | None
```

Retrieve user id by token if valid.

Token types:
- e_ver = Email verification
- p_rec = Password recovery

**Arguments**:

- `token` - Token id.
- `type` - Token type.
  

**Returns**:

  User id if found, otherwise None.

<a id="lib.database.Database.delete_user_tokens"></a>

#### delete\_user\_tokens

```python
def delete_user_tokens(user_id: int, type: Literal['e_ver', 'p_rec']) -> None
```

Delete all user tokens by type.

Token types:
- e_ver = Email verification
- p_rec = Password recovery

**Arguments**:

- `user_id` - User id.
- `type` - Token type.

<a id="lib.database.Database.add_repo_view"></a>

#### add\_repo\_view

```python
def add_repo_view(repo_id: str, visitor_hash: str, client: str,
                  location: str | None) -> bool
```

Create a new repo view.

**Arguments**:

- `repo_id` - Repo id.
- `visitor_hash` - Hash identifying visitor.
- `client` - Visitor cient type.
- `location` - Visitor location code.
  
  Retruns:
  True if view was added.

<a id="lib.database.Database.count_repo_views"></a>

#### count\_repo\_views

```python
def count_repo_views(repo_id: str) -> int
```

Count all repo views.

**Arguments**:

- `repo_id` - Repo id.
  
  Retruns:
  Count of repo views.

<a id="lib.database.Database.list_user_repo_views"></a>

#### list\_user\_repo\_views

```python
def list_user_repo_views(user_id: int,
                         offset: int = 0,
                         limit: int = 10) -> list[Views]
```

Retrieve all users repo views using filters.

**Arguments**:

- `user_id` - User id.
- `offset` - Amount rows to skip (default 0).
- `limit` - Limit of rows to return (default 10).
  

**Returns**:

  List of the Views interfaces.

<a id="lib.database.Database.count_user_repo_views"></a>

#### count\_user\_repo\_views

```python
def count_user_repo_views(user_id: int) -> int
```

Count all users repo views.

**Arguments**:

- `user_id` - User id.
  
  Retruns:
  Count of users repo views.

<a id="lib.track"></a>

# lib.track

Module provides functions for user information detection.

<a id="lib.track.detect_client"></a>

#### detect\_client

```python
def detect_client(ua: str) -> str
```

Detects client type based on user agent.

Possible client types are:
- bot
- firefox / firefox_mobile
- edge
- opera
- chrome / chrome_mobile
- safari
- unknown

**Arguments**:

- `ua` - User agent.
  

**Returns**:

  Client type.

<a id="lib.track.detect_location"></a>

#### detect\_location

```python
def detect_location(ip: str) -> str | None
```

Detects client location based on IP address.

**Arguments**:

- `ip` - IP address.
  

**Returns**:

  Location country code or None if could not determine.
  

**Notes**:

  Function makes an http request to online api.

<a id="lib.track.viewer_hash"></a>

#### viewer\_hash

```python
def viewer_hash(day: int,
                user_id: int | None = None,
                ip: str | None = None,
                ua: str | None = None) -> str
```

Generates uniqe viewer hash.

Generates daily uniqe viewer hash given for identification.
Requires combination of identification:
- user_id
- ip + ua
If both are given the user_id if preffered.

**Arguments**:

- `day` - Day number.
- `user_id` - Known user id.
- `ip` - User IP.
- `ua` - User agent.
  

**Returns**:

  Uniqe viewer hash.
  

**Raises**:

- `ValueError` - If user_id or (ip and ua) is not provided.

<a id="lib.auth"></a>

# lib.auth

Module provides authentication functions and authorization decotators for Flask endpoints.

<a id="lib.auth.safe_redirect_url"></a>

#### safe\_redirect\_url

```python
def safe_redirect_url(next_url: str | None) -> str
```

Gives safe redirect URL provided unknown redirect URL.

If `next_url` is not provided or it is marked as unsafe then function will return defaulr redirect URL `/dashboard`.

**Arguments**:

- `next_url` - Unknown redirect URL.
  

**Returns**:

  Safe redirect URL.

<a id="lib.auth.hash_password"></a>

#### hash\_password

```python
def hash_password(password: str) -> str
```

Hashes password cryptographic secure.

**Arguments**:

- `password` - Password to hash.
  

**Returns**:

  Hashed password.

<a id="lib.auth.check_password"></a>

#### check\_password

```python
def check_password(password: str, hashed_password: str) -> bool
```

Checks if given passwords match.

**Arguments**:

- `password` - Text password.
- `hashed_password` - Hashed password.
  

**Returns**:

  True if passwords match.

<a id="lib.auth.get_session_expiriation"></a>

#### get\_session\_expiriation

```python
def get_session_expiriation(role: str) -> int
```

Gives session expiriation timestamp based on role.

In `dev` enviroment function lifespan will be 24h.
In `dev` enviroment function lifespan will be:
- 1h for regular users.
- 20min for admins.

**Arguments**:

- `role` - User role code.
  

**Returns**:

  Session expiriation timestamp.

<a id="lib.render"></a>

# lib.render

Module provides utilities for rendering files and repository templates.

<a id="lib.render.Section"></a>

## Section Objects

```python
class Section()
```

Repository section template data parent class.

**Arguments**:

- `path` - Path to repository resource.

<a id="lib.render.FileSection"></a>

## FileSection Objects

```python
class FileSection(Section)
```

Repository file section template data.

**Arguments**:

- `path` - Path to repository resource.

<a id="lib.render.FileSection.is_text"></a>

#### is\_text

```python
def is_text() -> bool
```

Is file a text file.

**Returns**:

  True if file is a text file.

<a id="lib.render.FileSection.load_content"></a>

#### load\_content

```python
def load_content() -> Markup
```

Gives file content safe for html.

**Returns**:

  File content safe for html

<a id="lib.render.DirSection"></a>

## DirSection Objects

```python
class DirSection(Section)
```

Repository directory section template data.

**Arguments**:

- `path` - Path to repository resource.

<a id="lib.render.DirSection.find_readme_child"></a>

#### find\_readme\_child

```python
def find_readme_child() -> FileSection | None
```

Finds readme file in direct children of directory.

**Returns**:

  If exists an `FileSection` of readme child otherwise None.

<a id="lib.render.build_section"></a>

#### build\_section

```python
def build_section(path: Path) -> Section
```

Builds section template data class of repository resource.

**Arguments**:

- `path` - Path to repository resource.
  

**Returns**:

  Section template data class.

<a id="lib.render.is_text"></a>

#### is\_text

```python
def is_text(path: Path) -> bool
```

Checks if path is a text file.

**Arguments**:

- `path` - Patch to check.
  

**Returns**:

  True if path is a text file.

<a id="lib.render.detect_file_type"></a>

#### detect\_file\_type

```python
def detect_file_type(path: Path) -> str
```

Detects file type.

**Arguments**:

- `path` - Path to file.
  

**Returns**:

  File type (`doc`, `code`, `markdown`, `image`, `archive`, `other`).
  

**Raises**:

- `ValueError` - If provided path is not a file.

<a id="lib.render.build_parentchain"></a>

#### build\_parentchain

```python
def build_parentchain(path: Path, repo_root: Path) -> list[str]
```

Builds list of parent internal paths.

**Arguments**:

- `path` - Path to repositiry reosurce (in `extraced/`).
- `repo_root` - Repository path.
  

**Returns**:

  List of parent internal paths.

<a id="lib.render.render_markdown"></a>

#### render\_markdown

```python
def render_markdown(text: str) -> Markup
```

Renders markdown text.

**Arguments**:

- `text` - Text to render.
  

**Returns**:

  Renderd markdown text, safe to use in html.

<a id="lib.render.render_code"></a>

#### render\_code

```python
def render_code(text: str, file_name: str) -> Markup
```

Renders code (highlights) text.

**Arguments**:

- `text` - Text to render.
- `file_name` - File name (used for type detection).
  

**Returns**:

  Renderd code text, safe to use in html.

<a id="lib.render.get_prerendered"></a>

#### get\_prerendered

```python
def get_prerendered(path: Path) -> Path | None
```

Gives path to prerenderd file form repository resource file path.

**Arguments**:

- `path` - Repository resource file path.
  

**Returns**:

  Prerenderd file path if exists otherwise None.
  

**Raises**:

- `ValueError` - If given path is not a file or is not in `repo/extracted/`.

<a id="lib.utils"></a>

# lib.utils

Module provides basic utility functions for user input validation and parsing data for templates.

<a id="lib.utils.is_valid_repo_url"></a>

#### is\_valid\_repo\_url

```python
def is_valid_repo_url(url: str) -> bool
```

Validate repository URL.

Valid URL will follow this pattern:
- `https://github.com/user/repo.git`
- `git@github.com:user/repo.git`.

**Arguments**:

- `url` - URL to validate.
  

**Returns**:

  True if URL is valid.
  

**Notes**:

  This function checks only format. It does not verify
  URL resource existence.

<a id="lib.utils.is_valid_email"></a>

#### is\_valid\_email

```python
def is_valid_email(email: str) -> bool
```

Validate email.

**Arguments**:

- `email` - Email to validate.
  

**Returns**:

  True if email is valid.
  

**Notes**:

  This function checks only format. It does not verify
  domain existence or mailbox availability.

<a id="lib.utils.is_valid_password"></a>

#### is\_valid\_password

```python
def is_valid_password(password: str) -> str | None
```

Validate password.

Password is valid when meets the following conditions:
- Minimum 12 characters long
- Maximum 128 characters long
- Does not have leading or trailling spaces

**Arguments**:

- `password` - Password to validate.
  

**Returns**:

  Error message if password is invalid, otherwise None.

<a id="lib.utils.is_vaild_status"></a>

#### is\_vaild\_status

```python
def is_vaild_status(status: str) -> bool
```

Validate status.

**Arguments**:

- `status` - Status to validate.
  

**Returns**:

  True if status if valid.

<a id="lib.utils.timestamp_to_str"></a>

#### timestamp\_to\_str

```python
def timestamp_to_str(timestamp: int) -> str
```

Parses timestamp to string format.

**Arguments**:

- `timestamp` - Timestamp to parse.
  

**Returns**:

  Timestamp in string format.

<a id="lib.utils.size_to_str"></a>

#### size\_to\_str

```python
def size_to_str(size: int | None) -> str
```

Parses size to string format.

Returns number with greatest unit suffix (B, KB, MB, GB), rounding down.
Returns "?" if size is None.

**Arguments**:

- `size` - Size to parse.
  

**Returns**:

  Size in string format.

<a id="lib.utils.code_to_status"></a>

#### code\_to\_status

```python
def code_to_status(code: str)
```

Parses status code to string format.

**Arguments**:

- `code` - Status code to parse.
  

**Returns**:

  Status in string format.

<a id="lib.utils.code_to_role"></a>

#### code\_to\_role

```python
def code_to_role(code: str) -> str
```

Parses role code to string format.

**Arguments**:

- `code` - Role code to parse.
  

**Returns**:

  Role in string format.

<a id="lib.utils.builds_activity_to_readable"></a>

#### builds\_activity\_to\_readable

```python
def builds_activity_to_readable(builds: list[BuildActivity])
```

Parses BuildActivity list to string formatted tuple for template display.

**Arguments**:

- `builds` - BuildActivity list to parse.
  

**Returns**:

  String formatted tuple.

<a id="lib.utils.users_activity_to_readable"></a>

#### users\_activity\_to\_readable

```python
def users_activity_to_readable(users: list[UserActivity])
```

Parses UserActivity list to string formatted tuple for template display.

**Arguments**:

- `builds` - UserActivity list to parse.
  

**Returns**:

  String formatted tuple.

<a id="lib.utils.repos_activity_to_readable"></a>

#### repos\_activity\_to\_readable

```python
def repos_activity_to_readable(repos: list[RepoActivity])
```

Parses RepoActivity list to string formatted tuple for template display.

**Arguments**:

- `builds` - RepoActivity list to parse.
  

**Returns**:

  String formatted tuple.

<a id="lib.utils.views_to_readable"></a>

#### views\_to\_readable

```python
def views_to_readable(views: list[Views])
```

Parses Views list to string formatted tuple for template display.

**Arguments**:

- `builds` - Views list to parse.
  

**Returns**:

  String formatted tuple.

<a id="lib.database_rows"></a>

# lib.database\_rows

Module provides data types fetched by `lib.database` module.

<a id="lib.flask_helpers"></a>

# lib.flask\_helpers

Module provides Flask helper functoins for managing Flask endpoints.

<a id="lib.flask_helpers.login_required"></a>

#### login\_required

```python
def login_required()
```

Allows only logged-in users.

<a id="lib.flask_helpers.verification_required"></a>

#### verification\_required

```python
def verification_required()
```

Allows only verified users.

<a id="lib.flask_helpers.role_required"></a>

#### role\_required

```python
def role_required(role: str)
```

Allows only users with given role.

**Arguments**:

- `role` - Allowed role code.

<a id="lib.flask_helpers.not_banned_required"></a>

#### not\_banned\_required

```python
def not_banned_required()
```

Allows only not banned users.

<a id="lib.flask_helpers.use_cache"></a>

#### use\_cache

```python
def use_cache()
```

Adds ETag caching.

<a id="lib.logger"></a>

# lib.logger

Module provides functions for simple stdout event logging.

<a id="lib.logger.Level"></a>

## Level Objects

```python
class Level()
```

Levels for logging.

<a id="lib.logger.Event"></a>

## Event Objects

```python
class Event()
```

Events for logging.

<a id="lib.logger.Code"></a>

## Code Objects

```python
class Code()
```

Codes for logging.

<a id="lib.logger.USER_MESSAGES"></a>

#### USER\_MESSAGES

Default user messages per Code.

<a id="lib.logger.DEFAULT_LEVELS"></a>

#### DEFAULT\_LEVELS

Default levels per Code.

<a id="lib.logger.log"></a>

#### log

```python
def log(event: str,
        level: str = "INFO",
        code: str | None = None,
        build_id: int | None = None,
        repo_id: str | None = None,
        user_id: int | None = None,
        extra: dict[str, Any] | None = None) -> None
```

Logs given event to stdout.

Prints logs to stdout. If enviroment is set to `prod` then logs with `DEBUG` level will be skipped.

**Arguments**:

- `event` - Event to log (use `Event` class).
- `level` - Log level (use `Level` class, otherwise will use default)).
- `code` - Logs code (use `Code` class, otherwise will use default).
- `build_id` - Build id correlated to this event (if revelant).
- `repo_id` - Repo id correlated to this event (if revelant).
- `user_id` - User id correlated to this event (if revelant).
- `extra` - Additional values to include in logged event.

<a id="lib.emails"></a>

# lib.emails

Module provides interface for sending emails using intents.

<a id="lib.emails.EmailIntent"></a>

## EmailIntent Objects

```python
class EmailIntent()
```

Email intent codes.

<a id="lib.emails.send_email"></a>

#### send\_email

```python
def send_email(intent: str, *, to: str, is_verified: bool, user_id: int,
               **ctx) -> None
```

Sends email.

**Arguments**:

- `intent` - Email intent code (use `EmailInetent` class).
- `to` - Email recipient (email address).
- `is_verified` - Is receiving user verified.
- `user_id` - Id of receiving user.
- `ctx` - Values used for email rendering.
  

**Raises**:

- `ValueError` - When provided email intent is invalid.
- `ValueError` - When intent requires verified user and user is not verified.
- `PermissionError` - When intent required rendering field is not provided.

