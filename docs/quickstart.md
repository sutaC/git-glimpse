# Quick Start

This guide takes about 3 minutes to complete.

## 1. Register an account

1. Visit `/register` page and provide required information:
    - Username and email must be unique
    - Password must be at least 12 characters

2. Verify by email:
    - You will receive a verification email
    - Open the link in the email to activate your account

## 2. Add a private GitHub repository

1. Select the private repository you want to share.

> Snapshots are public and read-only. **Do not include secrets.**

2. Add a deploy key on GitHub:
    - Go to `Settings > Deploy keys`
    - Add a **read-only** deploy key
    - Follow the official [GitHub guide](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/managing-deploy-keys#set-up-deploy-keys) if needed

> If the repository is public, you can skip the deploy key and use an **HTTPS URL** (e.g. `https://github.com/user/repo.git`).

3. In Git Glimpse:
    - Go to `Dashboard > Add repository`
    - Enter the repository **SSH URL** (e.g. `git@github.com:user/repo.git`)
    - Paste the **private deploy key** (the key you generated locally)
    - Submit the form

4. After submission:
    - You will be redirected to the repository details page
    - A build will be scheduled automatically

5. When the build succeeds:
    - The snapshot becomes publicly accessible
    - If the build fails, try again later
    - If you receive a violation error, check [Repository Limits](limits.md)

## 3. Share the public link

1. Open the repository details page

2. Click **View**

3. Copy the URL and share it

## 4. Update the snapshot

Snapshots do not update automatically.

1.  Go to the repository details page

2.  Click **Build**

3.  When the build finishes, the same URL will show the updated content
