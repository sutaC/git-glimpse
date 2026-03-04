# FAQ

## General

**Q:** Is Git Glimpse a backup service?  
**A:** No. Snapshots are read-only public copies and contain only the latest state of the default branch.

**Q:** Can I share repositories with secrets?  
**A:** No. Snapshots are public. Do not include secrets or sensitive data.

## Builds

**Q:** Do snapshots update automatically?  
**A:** No. You must trigger a new build for each update.

**Q:** How long does a build take?  
**A:** Depends on repo size and file count. Maximum clone: 30s, scan: 10s, render: 20s.

**Q:** Why did my build fail?  
**A:** Check the [Troubleshooting Builds](troubleshooting.md) page for common causes.

## Repositories

**Q:** Can I include submodules?  
**A:** No. Submodules are not supported.

**Q:** Can I add the same repository twice?  
**A:** No. Each repository can have only one snapshot per user.

**Q:** What files are included in snapshots?  
**A:** Only files present on the default branch at build time. `.git` directories are removed.

## Accounts & Access

**Q:** How long are snapshots available?  
**A:** Snapshots remain while the owner account is active. Inactive accounts are disabled after 97 days.

**Q:** Can other users trigger builds on my repositories?  
**A:** No. Only the owner can schedule builds.

## Troubleshooting & Support

**Q:** I got a timeout or violation error, what should I do?  
**A:** See [Troubleshooting Builds](troubleshooting.md) for fixes.

**Q:** Who can I contact for help?  
**A:** Send an email to `contact@sutac.pl`.
