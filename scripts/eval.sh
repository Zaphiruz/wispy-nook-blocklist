#!/usr/bin/env bash
# Monthly blocklist eval. Pulls 30 days of allowed Pi-hole queries from LC3,
# cross-references against the reference lists in sources.txt, and appends new
# ad/tracker candidates to blocklist.txt.
#
# Env:
#   LC3_SSH_HOST       (default: lc3-blocklist) ssh alias with forced-command access
#   REPO_ROOT          (default: current repo root)
#
# Exit 0 and prints "no new candidates" if nothing to add.
# Exit 0 and prints "added N candidates" after mutating blocklist.txt + reports/.

set -euo pipefail

LC3_SSH_HOST=${LC3_SSH_HOST:-lc3-blocklist}
REPO_ROOT=${REPO_ROOT:-$(git rev-parse --show-toplevel)}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

echo "repo root: $REPO_ROOT"
echo "work dir:  $WORK"

echo "[1/5] fetching 30-day allowed queries from $LC3_SSH_HOST"
ssh -o BatchMode=yes "$LC3_SSH_HOST" > "$WORK/allowed.csv"
wc -l "$WORK/allowed.csv"

echo "[2/5] downloading reference blocklists"
mkdir -p "$WORK/refs"
i=0
while IFS= read -r url; do
  case "$url" in ''|\#*) continue;; esac
  i=$((i+1))
  echo "  - $url"
  curl -fsSL --max-time 60 -o "$WORK/refs/ref-$i.raw" "$url"
done < "$REPO_ROOT/sources.txt"

echo "[3/5] normalizing + ranking candidates"
python3 "$REPO_ROOT/scripts/rank.py" \
  --allowed "$WORK/allowed.csv" \
  --refs-dir "$WORK/refs" \
  --existing "$REPO_ROOT/blocklist.txt" \
  --out-blocklist "$WORK/new-additions.txt" \
  --out-report   "$WORK/report.md"

count=$(wc -l < "$WORK/new-additions.txt" | tr -d ' ')
if [ "$count" = 0 ]; then
  echo "[4/5] no new candidates — exiting"
  echo "NEW_COUNT=0" >> "${GITHUB_OUTPUT:-/dev/null}" || true
  exit 0
fi

echo "[4/5] appending $count candidates to blocklist.txt"
# Append with a dated header
month=$(date -u +%Y-%m)
{
  echo ""
  echo "# ---- Proposed $month ----"
  cat "$WORK/new-additions.txt"
} >> "$REPO_ROOT/blocklist.txt"

echo "[5/5] writing report to reports/$month.md"
mkdir -p "$REPO_ROOT/reports"
cp "$WORK/report.md" "$REPO_ROOT/reports/$month.md"

echo "NEW_COUNT=$count" >> "${GITHUB_OUTPUT:-/dev/null}" || true
echo "MONTH=$month"     >> "${GITHUB_OUTPUT:-/dev/null}" || true
echo "done. added $count candidates for $month."
