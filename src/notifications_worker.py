from src.lib.utils import timestamp_to_str
from src.lib import emails, logger as lg
from src.globals import DATABASE_PATH
from src.lib.database import Database
from time import time

# --- main
def send_notifications() -> None:
    """Send notifications to all relevant users."""
    lg.log(lg.Event.NOTIFICATIONS_STARTED)
    tsi = time()
    ts = timestamp_to_str(int(tsi))
    count = 0
    try:
        db = Database(DATABASE_PATH, raw_mode=True)
        not_data = db.list_user_notifications_data()
        for und in not_data:
            emails.send_email(
                emails.EmailIntent.VIEWS_NOTIFICATION, 
                to=und.email,
                is_verified=True,
                user_id=und.id,
                user=und.login,
                timestamp=ts,
                views=und.views
            )
            count+=1
        db._close()
    except Exception as e:
        duration = int(time() - tsi)
        lg.log(lg.Event.NOTIFICATIONS_ERROR, lg.Level.ERROR, extra={"duration": duration, "send": count})
        return
    duration = int(time() - tsi)
    lg.log(lg.Event.NOTIFICATIONS_FINISHED, extra={"duration": duration, "send": count})

if __name__ == "__main__":
    send_notifications()