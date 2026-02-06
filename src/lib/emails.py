from email.message import EmailMessage
from dataclasses import dataclass
from markupsafe import escape
import lib.logger as lg
import smtplib
import os

_ENV = os.environ.get("ENV", "dev")
_DOMAIN = os.environ.get("DOMAIN", "")
SMTP_HOST = os.environ["SMTP_HOST"]                 # REQUIRED
SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))   # REQUIRED
SMTP_USER = os.environ["SMTP_USER"]                 # REQUIRED
SMTP_PASS = os.environ["SMTP_PASS"]                 # REQUIRED
SMTP_FROM = os.environ["SMTP_FROM"]                 # REQUIRED

# intents
class EmailIntent:
    EMAIL_VERIFICATION = "intent.email.verification"
    PASSWORD_RECOVERY = "intent.password.recovery"
    INACTIVE_ACCOUNT = "intent.inactive.account"
    REPO_REMOVAL = "intent.repo.removal"

@dataclass(frozen=True)
class EmailIntentSpec:
    subject: str
    requires_verified: bool
    required_fields: frozenset[str]

INTENTS: dict[str, EmailIntentSpec] = {
    EmailIntent.EMAIL_VERIFICATION: EmailIntentSpec(
        subject="Git Glimpse - Email verification",
        requires_verified=False,
        required_fields=frozenset({"user", "token", "expires"})
    ),
    EmailIntent.PASSWORD_RECOVERY: EmailIntentSpec(
        subject="Git Glimpse - Password recovery",
        requires_verified=True,
        required_fields=frozenset({"user", "token", "expires"})
    ),
    EmailIntent.INACTIVE_ACCOUNT: EmailIntentSpec(
        subject="Git Glimpse - Inactive account",
        requires_verified=True,
        required_fields=frozenset({"user", "last_login"})
    ),
    EmailIntent.REPO_REMOVAL: EmailIntentSpec(
        subject="Git Glimpse - Removing repositories",
        requires_verified=True,
        required_fields=frozenset({"user"})
    )
}

# templates
def _get_base_url() -> str:
    if _ENV == "prod": return f"https://{_DOMAIN}"
    return "http://127.0.0.1:5000"

def tpl_email_verification(*, user: str, token: str, expires: str) -> str:
    return f'''
        Hello {escape(user)}!

        This is verification email for Git Glimpse. 
        To verify your email, open this link:
        {escape(_get_base_url()+f"/verify?t={token}")}
        This link will expire on {escape(expires)}.
    '''

def tpl_password_recovery(*, user: str,  token: str, expires: str) -> str:
    return f'''
        Hello {escape(user)}!

        This is password recovery email for Git Glimpse. 
        To reset your password, open this link:
        {escape(_get_base_url()+f"/password/reset?t={token}")}
        This link will expire on {escape(expires)}.
    '''

def tpl_inactive_account(*, user: str,  last_login: str) -> str:
    return f'''
        Hello {escape(user)}!

        We noticed that your Git Glimpse account was inactive for a long time. 
        Over 90 days have passed since your last login ({escape(last_login)})
        To keep your accounts repos avaliable, you only need to login to your account:  
        {escape(_get_base_url()+'/login')}

        If you will still stay inactive, after 7 days after sending this email your repos will become hiddend and removed from our servers. 
    '''

def tpl_repo_removal(*, user: str) -> str:
    return f'''
        Hello {escape(user)}!

        Due to your long inactivity on Git Glimpse we are removing your repositories from our servers.
        They will no longer be visible, however if you would like them back, you can still login, and create a new build to make them visible again.
    '''
        

TEMPLATES = {
    EmailIntent.EMAIL_VERIFICATION: tpl_email_verification,
    EmailIntent.PASSWORD_RECOVERY: tpl_password_recovery,
    EmailIntent.INACTIVE_ACCOUNT: tpl_inactive_account,
    EmailIntent.REPO_REMOVAL: tpl_repo_removal
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
