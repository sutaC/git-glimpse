# Git Glimpse

Git Glimpse is a simple self-hosted application for sharing private GitHub repositories with friends via public links.

> Currently in development

## Requiraments

- Docker
- Docker Compose
- Cron (optional, required for automated cleanup in production)

## Enviroment configuration

An environment file is **required** for the application to run.

1. Copy the example file:
    ```bash
    cp .env.example .env
    ```
2. Fill in required values described in `.env.example`
    > In development mode, emails are printed to stdout — no SMTP server is required.

## Development

Development uses Docker with live reload and mounted source code.

1. Build image:
    ```bash
    docker build -t git-glimpse .
    ```
2. Start the app (dev mode):
    ```bash
    docker compose up
    ```
3. Cleanup worker (manual):
    ```bash
     scripts/run_cleanup.sh
    ```
4. Reset root password:

    ```bash
     src/run_root_passwd.sh
    ```

    > After initialising database the **only** way to change root account password.

---

## Production

Production uses the same Docker image, without dev overrides.
To run production:

1. Build image:
    ```bash
    docker build -t git-glimpse .
    ```
2. Setup cron jobs:
    ```bash
    ./scripts/setup_cron.sh
    ```
    > Runs cleanup worker once per day
3. Start the app:
    ```bash
    docker-compose -f docker-compose.yml up
    ```
