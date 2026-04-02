#!/bin/bash
# remove_cron.sh - removes cleanup_worker cron job
set -e

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CRON_CMD_CLEANUP="$PROJECT_DIR/scripts/run_cleanup.sh >> $PROJECT_DIR/logs/cleanup.log 2>&1"
CRON_CMD_NOTIFICATIONS="$PROJECT_DIR/scripts/run_notifications.sh >> $PROJECT_DIR/logs/notifications.log 2>&1"

(crontab -l 2>/dev/null | grep -vF "$CRON_CMD_CLEANUP") | crontab -
(crontab -l 2>/dev/null | grep -vF "$CRON_CMD_NOTIFICATIONS") | crontab -

echo "Cron jobs removed."
