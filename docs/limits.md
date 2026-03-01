# Repository Limits

Git Glimpse enforces strict limits to keep builds fast and the service stable.

## Size limits

| Limit                        | Value  |
| ---------------------------- | ------ |
| Maximum repository size      | 100 MB |
| Maximum file size (included) | 10 MB  |

Files larger than the limit will fail validation.

## Structure limits

| Limit                   | Value  |
| ----------------------- | ------ |
| Maximum files           | 10,000 |
| Maximum directories     | 5,000  |
| Maximum directory depth | 20     |

Repositories exceeding these limits will fail validation.

## Time Limits

| Limit               | Value      |
| ------------------- | ---------- |
| Maximum clone time  | 30 seconds |
| Maximum scan time   | 10 seconds |
| Maximum render time | 20 seconds |

If any step exceeds its time limit, the build is aborted.

## Unsupported Content

The following are not allowed:

- Git submodules
- Symlinks
- FIFOs (named pipes)
- Character devices
- Block devices
- Sockets

These will cause the build to fail validation.

## What Is Included

- Only the default branch
- Only the latest state (no history)
- Only files present at build time

## Rendering Limits

Rendering limits apply only to syntax highlighting and Markdown previews. Files are still downloadable.

| Limit                                | Value       |
| ------------------------------------ | ----------- |
| Maximum file size for HTML rendering | 1 MB        |
| Rendered file types                  | text, image |

### Code highlight extensions:

`.py`, `.js`, `.ts`, `.go`, `.rs`, `.java`, `.c`, `.cpp`,
`.h`, `.hpp`, `.cs`, `.sh`, `.bash`, `.zsh`,
`.html`, `.css`, `.scss`, `.json`, `.yml`, `.yaml`,
`.toml`, `.ini`, `.cfg`, `.sql`

### Markdown rendering extensions:

`.md`

Files not falling in any of these categories will not have special highlighting/rendering.

## Tips for a Successful Build

- Remove large assets (videos, datasets)
- Avoid deep directory nesting
- Keep repositories under 100 MB
- Use `.gitignore` to exclude unnecessary files

## Build Outcomes

A build can:

- **Succeed** – snapshot is generated
- **Violation** – repository violates limits, contains unsupported content, or exceeded time limits
- **Fail** – build failed unexpectedly

Having problems with troubleshooting your builds? See [Troubleshooting Builds](troubleshooting.md).
