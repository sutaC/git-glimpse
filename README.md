# Git Glimpse

Simple aplication for sharing GitHub private repos with your firends via public link

> Currently in development

## Preparing project

1. Create venv: `python -m venv .venv`
1. Download dependencies: `pip install -r requiraments.txt`

## Env

Env template can be found in [template.env](template.env), which provides required fields with description for `.env` file.

### Production

Application uses smtp server to send emails to users, you can configure smtp options in `.env`.

Additionally, for sending correct urls, you will need to specify your domain in `.env`.

## Development

0.  Activate venv: `source .venv/bin/activate`
1.  Run web server: `flask --app src/app.py --debug run`
    - Web app handing requests
2.  Run build worker: `python3 src/build_worker.py`
    - In intervals checks for pending builds and builds them
    - **Required** for service to function
3.  \* To run cleanup: `python3 src/cleanup_worker.py`
    - Cleans dangling data, meant to run periodically, like once a day, to prevent storing garbage data
4.  \* Root password reset: `python3 src/root_passwd.py`
    - After initialising database the **only** option for changin root user password is via given script
5.  \* Emails in 'dev' mode are passed to stdout, so for local development you will **not need smtp server**
