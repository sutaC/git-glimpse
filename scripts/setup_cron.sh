#!/bin/bash
# setup_cron.sh - adds cleanup_worker cron job
set -e

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

mkdir -p "$PROJECT_DIR/logs"

CRON_JOB_CLEANUP="0 2 * * * $PROJECT_DIR/scripts/run_cleanup.sh >> $PROJECT_DIR/logs/cleanup.log 2>&1"
CRON_JOB_NOTIFICATIONS="0 10 * * * $PROJECT_DIR/scripts/run_notifications.sh >> $PROJECT_DIR/logs/notifications.log 2>&1"

# Cleanup
if (crontab -l 2>/dev/null | grep -F "$PROJECT_DIR/scripts/run_cleanup.sh"); then
    echo "Cleanup cron job already exists."
else 
    (crontab -l 2>/dev/null; echo "$CRON_JOB_CLEANUP") | crontab -
    echo "Cleanup worker cron job installed."
fi
# Notifications
if (crontab -l 2>/dev/null | grep -F "$PROJECT_DIR/scripts/run_notifications.sh"); then
    echo "Notifications cron job already exists."
else 
    (crontab -l 2>/dev/null; echo "$CRON_JOB_NOTIFICATIONS") | crontab -
    echo "Notifications worker cron job installed."
fi
