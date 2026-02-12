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

Development uses Docker with:

- bind-mounted source code

- bind-mounted ./data directory

- live reload for the web app and workers

---

**To run dev**:

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
    docker compose --profile manual run --rm cleanup_worker
    ```
4. Reset root password:

    ```bash
    ./scripts/run_root_passwd.sh --password '<password>'
    ```

    > After initialising database the **only** way to change root account password.

## Production

Production uses the same image with different volume mappings and stricter filesystem settings.

Data is stored on a dedicated host path `/mnt/git-glimpse-data` via docker-compose.prod.yml

---

**To run production:**

1. Build image:
    ```bash
    docker build -t git-glimpse .
    ```
2. Setup storage (one time, requires sudo privliges)

    ```bash
    ./scripts/setup_storage.sh
    ```

3. Setup cron jobs:
    ```bash
    ./scripts/setup_cron.sh
    ```
    > Runs cleanup worker once per day
4. Start the app:
    ```bash
    docker-compose -f docker-compose.yml -f docker-compose.prod.yml up
    ```
5. Reset root password:

    ```bash
    PROD=1 ./scripts/run_root_passwd.sh --password '<password>'
    ```

    > After initialising database the **only** way to change root account password.

## Removing production systems

To completely remove the production setup, use the provided helper scripts:

- `remove_corn.sh`
    > Removes the scheduled cron job responsible for running the cleanup worker.
- `remove_storage.sh`
    > Deletes the external production data directory (`/mnt/git-glimpse-data`).  
    > This will **permanently remove**:
    >
    > - the SQLite database
    > - all stored repositories and artifacts
    > - any related runtime data
    >
    > **Requires `sudo` privileges** and is **destructive**.  
    > Make sure you have backups before running this script.

---

**Recomended order:**

1. Stop the running containers:
    ```bash
    docker compose down
    ```
2. Remove the cron job:
    ```bash
    ./scripts/remove_cron.sh
    ```
3. Remove the storage:
    ```bash
    sudo ./scripts/remove_storage.sh
    ```

After these steps, the production environment will be fully removed.
