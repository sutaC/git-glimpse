from email.message import EmailMessage
from dataclasses import dataclass
from markupsafe import escape
import src.lib.logger as lg
import smtplib
import os

_ENV = os.environ.get("ENV", "dev")
_DOMAIN = os.environ.get("DOMAIN", "")
_CONTACT = os.environ.get("CONTACT_EMAIL", "")
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
SMTP_FROM = os.environ.get("SMTP_FROM", "")

# intents
class EmailIntent:
    EMAIL_VERIFICATION = "intent.email.verification"
    PASSWORD_RECOVERY = "intent.password.recovery"
    INACTIVE_ACCOUNT = "intent.inactive.account"
    REPO_REMOVAL = "intent.repo.removal"
    ACCOUNT_BANNED = "intent.account.banned"
    ACCOUNT_UNBANNED = "intent.account.ubbanned"

@dataclass(frozen=True)
class EmailIntentSpec:
    subject: str
    requires_verified: bool
    required_fields: frozenset[str]

INTENTS: dict[str, EmailIntentSpec] = {
    EmailIntent.EMAIL_VERIFICATION: EmailIntentSpec(
        subject="Verify your email address - Git Glimpse",
        requires_verified=False,
        required_fields=frozenset({"user", "token", "expires"})
    ),
    EmailIntent.PASSWORD_RECOVERY: EmailIntentSpec(
        subject="Reset your Git Glimpse password",
        requires_verified=True,
        required_fields=frozenset({"user", "token", "expires"})
    ),
    EmailIntent.INACTIVE_ACCOUNT: EmailIntentSpec(
        subject="Your Git Glimpse account has been inactive",
        requires_verified=True,
        required_fields=frozenset({"user", "last_login"})
    ),
    EmailIntent.REPO_REMOVAL: EmailIntentSpec(
        subject="Your Git Glimpse repositories were removed due to inactivity",
        requires_verified=True,
        required_fields=frozenset({"user"})
    ),
    EmailIntent.ACCOUNT_BANNED: EmailIntentSpec(
        subject="Your Git Glimpse account has been banned",
        requires_verified=True,
        required_fields=frozenset({"user", "reason"})
    ),
    EmailIntent.ACCOUNT_UNBANNED: EmailIntentSpec(
        subject="Access restored to your Git Glimpse account",
        requires_verified=True,
        required_fields=frozenset({"user"})
    )
}

# templates
def _get_base_url() -> str:
    if _ENV == "prod": return f"https://{_DOMAIN}"
    return "http://127.0.0.1:5000"

def _email_footer() -> str:
    return f'''
—
Git Glimpse
{_get_base_url()}
'''

def tpl_email_verification(*, user: str, token: str, expires: str) -> str:
    return f'''
Hello {escape(user)},

Thanks for signing up for Git Glimpse.

To verify your email address, open the link below:
{escape(_get_base_url() + f"/verify?t={token}")}

This link expires on {escape(expires)}.

If you didn’t create this account, you can safely ignore this email.
{_email_footer()}
'''.strip()

def tpl_password_recovery(*, user: str,  token: str, expires: str) -> str:
    return f'''
Hello {escape(user)},

We received a request to reset your Git Glimpse password.

To choose a new password, open the link below:
{escape(_get_base_url() + f"/password/reset?t={token}")}

This link expires on {escape(expires)}.

If you didn’t request this reset, you can ignore this email.
{_email_footer()}
'''.strip()

def tpl_inactive_account(*, user: str,  last_login: str) -> str:
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

def tpl_repo_removal(*, user: str) -> str:
    return f'''
Hello {escape(user)},

Due to extended inactivity, your Git Glimpse repositories have been removed from our servers.

Your account is still active.
If you log in and create a new build, your repositories will become visible again.

Login here:
{escape(_get_base_url() + '/login')}
{_email_footer()}
'''.strip()

def tpl_account_banned(*, user: str, reason: str | None) -> str:
    return f'''
Hello {escape(user)},

Your Git Glimpse account has been banned by an administrator.

{f"Reason: {escape(reason)}" if reason else ""}

You no longer have access to your account or repositories.
{f"If you believe this is a mistake, contact us at {_CONTACT}." if _CONTACT else ""}

{_email_footer()}
'''.strip()

def tpl_account_unbanned(*, user: str) -> str:
    return f'''
Hello {escape(user)},

Your Git Glimpse account has been unbanned and access has been restored.

You can log in here:
{escape(_get_base_url() + '/login')}
{_email_footer()}
'''.strip()

TEMPLATES = {
    EmailIntent.EMAIL_VERIFICATION: tpl_email_verification,
    EmailIntent.PASSWORD_RECOVERY: tpl_password_recovery,
    EmailIntent.INACTIVE_ACCOUNT: tpl_inactive_account,
    EmailIntent.REPO_REMOVAL: tpl_repo_removal,
    EmailIntent.ACCOUNT_BANNED: tpl_account_banned,
    EmailIntent.ACCOUNT_UNBANNED: tpl_account_unbanned,
}

# functionality
def _send_backend_stdout(to: str, subject: str, body: str) -> None:
    print(f"------- to: '{to}'\n-- subject: '{subject}'")
    for line in body.splitlines():
        if line: print(f'>\t{line}')
    return

def _send_backend_smtp(to: str, subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["From"] = SMTP_FROM
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as smtp:
        smtp.starttls()
        smtp.login(SMTP_USER, SMTP_PASS)
        smtp.send_message(msg)
        
def render_email(intent: str, **ctx) -> str:
    tpl = TEMPLATES.get(intent)
    if not tpl: raise ValueError(f"No template for intent: {intent}")
    return tpl(**ctx)

def send_email(intent: str, *, to: str, is_verified: bool, user_id: int, **ctx) -> None:
    spec = INTENTS.get(intent)
    if not spec: raise ValueError("Unknown email intent")
    if spec.requires_verified and not is_verified: raise ValueError(f"Intent {intent} requires verification")
    missing = spec.required_fields - ctx.keys()
    if missing: raise ValueError(f"Missing fields for {intent}: {missing}")
    subject = spec.subject
    body = render_email(intent, **ctx)
    try:
        if _ENV == "prod": _send_backend_smtp(to, subject, body)
        else: _send_backend_stdout(to, subject, body)
        lg.log(lg.Event.EMAIL_SEND, user_id=user_id, extra={"intent": intent})
    except Exception as e:
        lg.log(lg.Event.EMAIL_SEND_FAILED, lg.Level.ERROR, user_id=user_id, extra={"intent": intent, "reason": str(e)})
