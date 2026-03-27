#!/bin/bash
# run_notifications.sh - wrapper to run notifications_worker in Docker
set -e

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

docker compose \
  -f "$PROJECT_DIR/docker-compose.yml" \
  -f "$PROJECT_DIR/docker-compose.prod.yml" \
  --profile manual \
  run --rm notifications_worker 2>/dev/null