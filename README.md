# wispy-nook-blocklist

Personal DNS blocklist that feeds Pi-hole on LC3. New candidates are proposed
monthly by scanning the last 30 days of Pi-hole queries and cross-referencing
against several reference blocklists.

## How it works

1. A monthly GitHub Actions workflow runs on the self-hosted runner `s2-blocklist`.
2. It SSHes to LC3 and pulls the 30-day allowed-query log from
   `/etc/pihole/pihole-FTL.db`.
3. It downloads the reference lists in `sources.txt` (OISD, 1Hosts Lite,
   Peter Lowe, AdGuard DNS).
4. It finds allowed domains that appear in a reference list (exact or wildcard
   parent match) and that aren't already in `blocklist.txt` or Pi-hole's
   `gravity.db`.
5. It appends new candidates to `blocklist.txt`, writes a report under
   `reports/`, and opens a PR.

Review the PR, delete anything you don't want blocked, merge. Pi-hole picks up
the updated raw URL on its next `pihole -g`.

## Files

- `blocklist.txt` — the authoritative list of extra domains to block. Served
  raw from `main` to Pi-hole as an adlist.
- `sources.txt` — reference blocklist URLs the eval cross-references against.
- `scripts/eval.sh` — the eval script.
- `.github/workflows/monthly-eval.yml` — scheduled trigger (1st of each month)
  plus manual `workflow_dispatch`.
- `reports/YYYY-MM.md` — per-run report with ranked candidates.

## Pi-hole configuration

Added as an adlist:
```
https://raw.githubusercontent.com/Zaphiruz/wispy-nook-blocklist/main/blocklist.txt
```

## Manual run

```
gh workflow run monthly-eval.yml --repo Zaphiruz/wispy-nook-blocklist
```
