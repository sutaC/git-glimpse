"""Module provides interface for sending emails using intents."""
from email.message import EmailMessage
from dataclasses import dataclass
from markupsafe import escape
from typing import Callable
import src.lib.logger as lg
import smtplib
import os

_ENV = os.environ.get("ENV", "dev")
_DOMAIN = os.environ.get("DOMAIN", "")
_CONTACT = os.environ.get("CONTACT_EMAIL", "")
_SMTP_HOST = os.environ.get("_SMTP_HOST", "")
_SMTP_PORT = int(os.environ.get("_SMTP_PORT", 587))
_SMTP_USER = os.environ.get("_SMTP_USER", "")
_SMTP_PASS = os.environ.get("__SMTP_PASS", "")
_SMTP_FROM = os.environ.get("_SMTP_FROM", "")

# --- intents ---
class EmailIntent:
    """Email intent codes."""
    EMAIL_VERIFICATION = "intent.email.verification"
    PASSWORD_RECOVERY = "intent.password.recovery"
    INACTIVE_ACCOUNT = "intent.inactive.account"
    REPO_REMOVAL = "intent.repo.removal"
    ACCOUNT_BANNED = "intent.account.banned"
    ACCOUNT_UNBANNED = "intent.account.ubbanned"
    VIEWS_NOTIFICATION = "intent.views.notification"

@dataclass(frozen=True)
class _EmailIntentSpec:
    """Email intent specs for sending."""
    subject: str
    requires_verified: bool
    required_fields: frozenset[str]

_INTENTS: dict[str, _EmailIntentSpec] = {
    EmailIntent.EMAIL_VERIFICATION: _EmailIntentSpec(
        subject="Verify your email address - Git Glimpse",
        requires_verified=False,
        required_fields=frozenset({"user", "token", "expires"})
    ),
    EmailIntent.PASSWORD_RECOVERY: _EmailIntentSpec(
        subject="Reset your Git Glimpse password",
        requires_verified=True,
        required_fields=frozenset({"user", "token", "expires"})
    ),
    EmailIntent.INACTIVE_ACCOUNT: _EmailIntentSpec(
        subject="Your Git Glimpse account has been inactive",
        requires_verified=True,
        required_fields=frozenset({"user", "last_login"})
    ),
    EmailIntent.REPO_REMOVAL: _EmailIntentSpec(
        subject="Your Git Glimpse repositories were removed due to inactivity",
        requires_verified=True,
        required_fields=frozenset({"user"})
    ),
    EmailIntent.ACCOUNT_BANNED: _EmailIntentSpec(
        subject="Your Git Glimpse account has been banned",
        requires_verified=True,
        required_fields=frozenset({"user", "reason"})
    ),
    EmailIntent.ACCOUNT_UNBANNED: _EmailIntentSpec(
        subject="Access restored to your Git Glimpse account",
        requires_verified=True,
        required_fields=frozenset({"user"})
    ),
    EmailIntent.VIEWS_NOTIFICATION: _EmailIntentSpec(
        subject="New activity on your Git Glimpse repositories",
        requires_verified=True,
        required_fields=frozenset({"user", "timestamp", "views"})
    )
}
"""Email inntent codes mapped to EmailIntentSepecs."""

# --- templating ---
def _get_base_url() -> str:
    """Gives base service URL.
    
    Returns:
        Base service URL.
    """
    if _ENV == "prod": return f"https://{_DOMAIN}"
    return "http://127.0.0.1:5000"

def _email_footer() -> str:
    """Gives email footer.
    
    Returns:
        Email footer.
    """
    return f'''
—
Git Glimpse
{_get_base_url()}
'''

def _tpl_email_verification(*, user: str, token: str, expires: str) -> str:
    """Renders template for verification email.
    
    Args:
        user: User login.
        token: Verification token.
        expires: Token expiriation date.

    Returns:
        Email content.
    """
    return f'''
Hello {escape(user)},

Thanks for signing up for Git Glimpse.

To verify your email address, open the link below:
{escape(_get_base_url() + f"/verify?t={token}")}

This link expires on {escape(expires)}.

If you didn’t create this account, you can safely ignore this email.
{_email_footer()}
'''.strip()

def _tpl_password_recovery(*, user: str,  token: str, expires: str) -> str:
    """Renders template for password recovery email.
    
    Args:
        user: User login.
        token: Password recovery token.
        expires: Token expiriation date.

    Returns:
        Email content.
    """
    return f'''
Hello {escape(user)},

We received a request to reset your Git Glimpse password.

To choose a new password, open the link below:
{escape(_get_base_url() + f"/password/reset?t={token}")}

This link expires on {escape(expires)}.

If you didn’t request this reset, you can ignore this email.
{_email_footer()}
'''.strip()

def _tpl_inactive_account(*, user: str,  last_login: str) -> str:
    """Renders template for inactive account email.
    
    Args:
        user: User login.
        last_login: Last login date.

    Returns:
        Email content.
    """
    return f'''
Hello {escape(user)},

Your Git Glimpse account has been inactive for over 90 days.
Your last login was on {escape(last_login)}.

To keep your repositories active, simply log in:
{escape(_get_base_url() + '/login')}

If no activity occurs within 7 days, your repositories will be hidden and removed from our servers.

Logging in at any time will prevent this.
{_email_footer()}
'''.strip()

def _tpl_repo_removal(*, user: str) -> str:
    """Renders template for repository removal email.
    
    Args:
        user: User login.

    Returns:
        Email content.
    """
    return f'''
Hello {escape(user)},

Due to extended inactivity, your Git Glimpse repositories have been removed from our servers.

Your account is still active.
If you log in and create a new build, your repositories will become visible again.

Login here:
{escape(_get_base_url() + '/login')}
{_email_footer()}
'''.strip()

def _tpl_account_banned(*, user: str, reason: str | None) -> str:
    """Renders template for account banned email.
    
    Args:
        user: User login.
        reason: Ban reason.

    Returns:
        Email content.
    """
    return f'''
Hello {escape(user)},

Your Git Glimpse account has been banned by an administrator.

{f"Reason: {escape(reason)}" if reason else ""}

You no longer have access to your account or repositories.
{f"If you believe this is a mistake, contact us at {_CONTACT}." if _CONTACT else ""}

{_email_footer()}
'''.strip()

def _tpl_account_unbanned(*, user: str) -> str:
    """Renders template for account unbanned email.
    
    Args:
        user: User login.

    Returns:
        Email content.
    """
    return f'''
Hello {escape(user)},

Your Git Glimpse account has been unbanned and access has been restored.

You can log in here:
{escape(_get_base_url() + '/login')}
{_email_footer()}
'''.strip()

def _tpl_views_notification(*, user: str, timestamp: str, views: int) -> str:
    """Renders template for views notification email.
    
    Args:
        user: User login.
        timestamp: Timestamp of notification.
        views: Repository views.

    Returns:
        Email content.
    """
    return f'''
Hello {escape(user)},

Your repositories on Git Glimpse got {escape(views)} new views in last 24 hours!

Measurement time: {escape(timestamp)}

You can check out new views here:
{escape(_get_base_url() + '/views')}

To change your notification preferences visit your profile:
{escape(_get_base_url() + '/user')}
{_email_footer()}
'''.strip()

_TEMPLATES: dict[str, Callable[..., str]] = {
    EmailIntent.EMAIL_VERIFICATION: _tpl_email_verification,
    EmailIntent.PASSWORD_RECOVERY: _tpl_password_recovery,
    EmailIntent.INACTIVE_ACCOUNT: _tpl_inactive_account,
    EmailIntent.REPO_REMOVAL: _tpl_repo_removal,
    EmailIntent.ACCOUNT_BANNED: _tpl_account_banned,
    EmailIntent.ACCOUNT_UNBANNED: _tpl_account_unbanned,
    EmailIntent.VIEWS_NOTIFICATION: _tpl_views_notification,
}
"""Template intent codes mapped to templating functions."""

def _render_email(intent: str, **ctx) -> str:
    """Renders email.
    
    Args:
        intent: Email intent code (email address).
        ctx: Values used for email rendering.

    Returns:
        Rendered email.

    Raises:
        ValueError: When invalid template intent code is provided.
    """
    tpl = _TEMPLATES.get(intent)
    if not tpl: raise ValueError(f"No template for intent: {intent}")
    return tpl(**ctx)

# --- sending ---
def _send_backend_stdout(to: str, subject: str, body: str) -> None:
    """Sends email to stdout.
    
    Args:
        to: Email recipient (email address).
        subject: Email subject.
        body: Email body.
    """
    print(f"------- to: '{to}'\n-- subject: '{subject}'")
    for line in body.splitlines():
        if line: print(f'>\t{line}')
    return

def _send_backend_smtp(to: str, subject: str, body: str) -> None:
    """Sends email via smtp.
    
    Args:
        to: Email recipient.
        subject: Email subject.
        body: Email body.
    """
    msg = EmailMessage()
    msg["From"] = _SMTP_FROM
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    with smtplib.SMTP(_SMTP_HOST, _SMTP_PORT, timeout=10) as smtp:
        smtp.starttls()
        smtp.login(_SMTP_USER, _SMTP_PASS)
        smtp.send_message(msg)

def send_email(intent: str, *, to: str, is_verified: bool, user_id: int, **ctx) -> None:
    """Sends email.

    Args:
        intent: Email intent code (use `EmailInetent` class).
        to: Email recipient (email address).
        is_verified: Is receiving user verified.
        user_id: Id of receiving user.
        ctx: Values used for email rendering.

    Raises:
        ValueError: When provided email intent is invalid.
        ValueError: When intent requires verified user and user is not verified.
        PermissionError: When intent required rendering field is not provided.
    """
    spec = _INTENTS.get(intent)
    if not spec: raise ValueError("Unknown email intent")
    if spec.requires_verified and not is_verified: raise PermissionError(f"Intent {intent} requires verification")
    missing = spec.required_fields - ctx.keys()
    if missing: raise ValueError(f"Missing fields for {intent}: {missing}")
    subject = spec.subject
    body = _render_email(intent, **ctx)
    try:
        if _ENV == "prod": _send_backend_smtp(to, subject, body)
        else: _send_backend_stdout(to, subject, body)
        lg.log(lg.Event.EMAIL_SEND, user_id=user_id, extra={"intent": intent})
    except Exception as e:
        lg.log(lg.Event.EMAIL_SEND_FAILED, lg.Level.ERROR, user_id=user_id, extra={"intent": intent, "reason": str(e)})
