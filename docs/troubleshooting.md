# Troubleshooting Builds

This page helps diagnose common build failures and how to fix them.

## Build Status Types

| Status    | Meaning                                                                           |
| --------- | --------------------------------------------------------------------------------- |
| Succeed   | Snapshot generated successfully                                                   |
| Violation | Repository violates limits, contains unsupported content, or exceeded time limits |
| Fail      | Unexpected internal error                                                         |

## Common Violation Causes

Match the error message shown on the repository details page with the sections below.

### Repository exceeds 100 MB limit

**Fix:** remove large files or reduce repository size below 100 MB

---

### One of your files exceeds 10 MB limit

**Fix:** remove or reduce files larger than 10 MB

---

### Repository contains more than 10,000 files

**Fix:** remove generated assets, vendor folders or datasets

---

### Repository contains more than 5,000 directories

**Fix:** remove generated assets, vendor folders or datasets

---

### Repository exceeds maximum directory depth of 20

**Fix:** flatten deeply nested folder structures

---

### Repository contains forbidden file type(s)

**Fix:** remove unsupported file types:

- Git submodules
- Symlinks
- FIFOs (named pipes)
- Character devices
- Block devices
- Sockets

---

### Repository cloning exceeded 30 seconds

**Fix:** reduce repository size or try again later

---

### Repository scanning exceeded 10 seconds

**Fix:** reduce repository size, file count or large text files

---

### Repository rendering exceeded 20 seconds

**Fix:** reduce repository size, file count or large text files

---

### Could not acquire repository lock, try again later

**Fix:** try again later

---

### Repository not found or private access denied

**Fix:**

- Ensure the URL is correct
- Ensure the deploy key is added to the repository
- Ensure the key is **read-only**
- Ensure you pasted the **private key**, not the public key

---

### Permission denied, check your deploy key access or if URL is correct

**Fix:**

- Ensure the URL is correct
- Ensure the deploy key is added to the repository
- Ensure the key is **read-only**
- Ensure you pasted the **private key**, not the public key

---

### Network error, try again later

**Fix:** try again later

---

## Unexpected Failures

If a build fails without a clear violation:

1. Retry the build
2. Wait a few minutes and try again
3. Contact the administrator if the issue persists
