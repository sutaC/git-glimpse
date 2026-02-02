from markupsafe import escape

class Subjects:
    EMAIL_VERIFICATION = "Git Glimpse - Email verification"
    PASSWORD_RECOVERY = "Git Glimpse - Password recovery"

def _print_email(to: str, subject: str, body:str):
    print(f"------- to: '{to}'\n-- subject: '{subject}'")
    for line in body.splitlines():
        if line: print(f'>\t{line}')

def send_email(to: str, subject: str, body: str):
    # Temporary for dev
    _print_email(to, subject, body)

def template_verification(user: str, expires: str, url: str):
    return f'''
        Hello {escape(user)}!

        This is verification email for Git Glimpse. 
        To verify your email, open this link:
        {escape(url)}
        This link will expire on {escape(expires)}.
    '''

def template_password_recovery(user: str, expires: str, url: str):
    return f'''
        Hello {escape(user)}!

        This is password recovery email for Git Glimpse. 
        To reset your password, open this link:
        {escape(url)}
        This link will expire on {escape(expires)}.
    '''
