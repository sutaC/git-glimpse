#!/bin/bash
# run_root_passwd_dev.sh - wrapper to run root_passwd in Docker
set -e

if [ "$PROD" = "1" ]; then
    docker compose \
        -f docker-compose.yml \
        -f docker-compose.prod.yml \
        --profile manual \
        run --rm root_passwd "$@"
else
    docker compose \
        --profile manual \
        run --rm root_passwd "$@"
fi