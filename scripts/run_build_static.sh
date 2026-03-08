#!/bin/bash
# run_build_static.sh - wrapper to run build_static in Docker
set -e

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$PROJECT_DIR/src/static/dist/"

mkdir -p $DIST

# For handling permission errors
chmod o+w $DIST

docker compose --profile manual run --rm build_static

chmod o-w $DIST