#!/bin/bash
# run_root_passwd.sh - wrapper to run root_passwd in Docker
set -e

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

docker run --rm \
    -v $PROJECT_DIR/data:/app/data \
    -v $PROJECT_DIR/scripts:/app/scripts \
    --env-file $PROJECT_DIR/.env \
    git-glimpse \
    python scripts/root_passwd.py "$@"