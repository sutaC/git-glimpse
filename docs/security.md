# Security Model

This page describes how Git Glimpse handles private repositories and access keys.

## Repository Access

- Private repositories are accessed using user-provided deploy keys
- Only the default branch is cloned
- Cloning is performed as a shallow clone
- Git history is not stored

## Deploy Key Handling

- Deploy keys are stored encrypted in the database
- Keys are used only during the build process
- Keys are never exposed in the web interface
- Read-only deploy keys are recommended

## Build Isolation

- Repository cloning and processing occurs in an isolated worker container
- The web application runs in a separate container
- Build environments use read-only filesystems where possible
- Storage is limited and separated per repository

## Data Storage

- The `.git` directory is removed after cloning
- Snapshots contain only repository files at build time
- Rendered HTML is generated from extracted content
- Temporary data is cleaned up by a periodic cleanup worker

## Public Snapshots

- Snapshots are publicly accessible via an unlisted link
- No authentication is required to view shared content
- Do not include secrets or sensitive data

## Account Lifecycle

- Snapshots remain available while the owner account is active
- When an account is deleted or disabled, all associated data is permanently removed
- After 90 days without activity an account is marked as inactive and warning email is send
- After 97 days without activity an account is automatically disabled and all user repositories become hidden

## What Git Glimpse Does Not Do

- Does not scan repositories for secrets
- Does not provide access control on public snapshots
- Is not a backup service
