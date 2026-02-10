#!/bin/bash
# run_cleanup.sh - wrapper to run cleanup_worker in Docker
set -e

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

docker run -itd --rm \
    -v $PROJECT_DIR/data:/app/data \
    --env-file $PROJECT_DIR/.env \
    git-glimpse \
    python -m src.cleanup_worker