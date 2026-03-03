from hashlib import sha256
from requests import get

def detect_client(ua: str) -> str:
    """Detects client type based on user agent.

    Possible client types are:
    - bot
    - firefox / firefox_mobile
    - edge
    - opera
    - chrome / chrome_mobile
    - safari
    - unknown

    Args:
        ua: User agent. 

    Returns:
        Client type.
    """
    ua = ua.lower()
    if "bot" in ua or "spider" in ua or "crawl" in ua:
        return "bot"
    if "firefox" in ua:
        return "firefox_mobile" if "mobile" in ua else "firefox"
    if "edg" in ua:
        return "edge"
    if "opr" in ua or "opera" in ua:
        return "opera"
    if "chrome" in ua:
        return "chrome_mobile" if "mobile" in ua else "chrome"
    if "safari" in ua:
        return "safari"
    return "unknown"

def detect_location(ip: str) -> str | None:
    """Detects client location based on IP address.

    Args:
        ip: IP address.

    Returns:
        Location country code or None if could not determine. 

    Notes:
        Function makes an http request to online api.
    """
    if ip == "127.0.0.1": return None
    try:
        r  = get(f"https://ipapi.co/{ip}/country", timeout=1)
        if r.status_code == 200:
            code = r.text.strip()
            return code if len(code) == 2 else None
    except Exception:
        pass
    return None

def viewer_hash(day: int, user_id: int | None = None, ip: str | None = None, ua: str | None = None) -> str:
    """Generates uniqe viewer hash.

    Generates daily uniqe viewer hash given for identification.
    Requires combination of identification:
    - user_id
    - ip + ua
    If both are given the user_id if preffered.

    Args:
        day: Day number.
        user_id: Known user id.
        ip: User IP.
        ua: User agent.

    Returns:
        Uniqe viewer hash.

    Raises:
        ValueError: If user_id or (ip and ua) is not provided. 
    """
    if not (user_id or (ip and ua)): raise ValueError("Values user_id or (ip and up) are required.")
    if user_id: return sha256(f"u:{user_id}:{day}".encode()).hexdigest()
    return sha256(f"a:{ip}:{ua}:{day}".encode()).hexdigest()
