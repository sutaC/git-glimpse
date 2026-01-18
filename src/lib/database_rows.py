from typing import Literal, NamedTuple, TypeVar

RowType = TypeVar("RowType")

# --- repos
class Repo(NamedTuple):
    repo_name: str
    url: str 
    user_id: int 
    created: int

class RepoRow(NamedTuple):
    id: str
    repo_name: str

class RepoClone(NamedTuple):
    user_id: int
    url: str
    ssh_key: str

# --- users
class User(NamedTuple):
    login: str 
    role: str 
    is_verified: bool

class UserAuth(NamedTuple):
    id: int
    password: str
    role: str

class Limits(NamedTuple):
    builds_repo_limit: int
    builds_user_limit: int
    repo_limit: int    

# --- sessions
class Session(NamedTuple):
    user_id: int 
    expires: int

# --- builds
class Build(NamedTuple):
    status: Literal['p', 's', 'v', 'f']
    timestamp: int 
    size: int | None

class Sizes(NamedTuple):
    size: int
    archive_size: int

class BuildActivity(NamedTuple):
    repo_id: str
    user_login: str
    status: Literal['p', 's', 'v', 'f']
    timestamp: int
