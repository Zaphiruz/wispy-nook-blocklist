#!/usr/bin/env python3
"""Rank candidate domains to add to the Pi-hole blocklist.

Inputs:
  --allowed  CSV of "domain|count" from Pi-hole FTL (status 2/3/14, last 30d)
  --refs-dir directory of raw reference blocklists (any format)
  --existing current blocklist.txt (comment-stripped domains are excluded)

Outputs:
  --out-blocklist newline-separated candidates sorted desc by hits, with
                  "<domain>    # matched <ref>, N hits" annotations.
  --out-report    markdown report with top candidates grouped by matched source.
"""
from __future__ import annotations

import argparse
import datetime
import os
import re
import sys
from collections import defaultdict

DOMAIN_RE = re.compile(r"^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$")


def normalize_line(line: str) -> str | None:
    s = line.strip()
    if not s or s.startswith("#") or s.startswith("!"):
        return None
    # Strip adblock markers
    s = re.sub(r"^\|\|", "", s)
    s = re.sub(r"\^.*$", "", s)
    # Strip wildcard prefix
    s = re.sub(r"^\*\.", "", s)
    # Strip hosts prefix
    s = re.sub(r"^(0\.0\.0\.0|127\.0\.0\.1)\s+", "", s)
    # Take first token (hosts files have "0.0.0.0 d # comment")
    s = s.split()[0] if s.split() else ""
    s = s.lower()
    if DOMAIN_RE.match(s):
        return s
    return None


def load_set(path: str) -> set[str]:
    out: set[str] = set()
    if not os.path.exists(path):
        return out
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            d = normalize_line(line)
            if d:
                out.add(d)
    return out


def load_refs(refs_dir: str) -> dict[str, set[str]]:
    refs: dict[str, set[str]] = {}
    if not os.path.isdir(refs_dir):
        return refs
    for name in sorted(os.listdir(refs_dir)):
        path = os.path.join(refs_dir, name)
        refs[name] = load_set(path)
    return refs


def load_existing(path: str) -> set[str]:
    """Load existing blocklist.txt — strip trailing comments."""
    out: set[str] = set()
    if not os.path.exists(path):
        return out
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            # Strip trailing "# ..." comment then normalize
            head = line.split("#", 1)[0]
            d = normalize_line(head) if head.strip() else None
            if d:
                out.add(d)
    return out


def load_allowed(path: str) -> list[tuple[str, int]]:
    rows: list[tuple[str, int]] = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            s = line.strip()
            if not s:
                continue
            if "|" not in s:
                continue
            domain, count = s.rsplit("|", 1)
            d = normalize_line(domain)
            try:
                n = int(count)
            except ValueError:
                continue
            if d:
                rows.append((d, n))
    return rows


def match(domain: str, ref: set[str]) -> tuple[str, str] | None:
    """Return (matched_as, match_type) if domain or any parent is in ref."""
    if domain in ref:
        return domain, "exact"
    parts = domain.split(".")
    for i in range(1, len(parts) - 1):
        parent = ".".join(parts[i:])
        if parent in ref:
            return parent, "wildcard"
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--allowed", required=True)
    ap.add_argument("--refs-dir", required=True)
    ap.add_argument("--existing", required=True)
    ap.add_argument("--out-blocklist", required=True)
    ap.add_argument("--out-report", required=True)
    ap.add_argument("--min-hits", type=int, default=1)
    args = ap.parse_args()

    allowed = load_allowed(args.allowed)
    existing = load_existing(args.existing)
    refs = load_refs(args.refs_dir)
    print(f"allowed domains: {len(allowed)}", file=sys.stderr)
    print(f"already in blocklist.txt: {len(existing)}", file=sys.stderr)
    for name, s in refs.items():
        print(f"  ref {name}: {len(s)}", file=sys.stderr)

    # Per-domain match
    raw_matches: list[dict] = []
    for domain, hits in allowed:
        if hits < args.min_hits:
            continue
        if domain in existing:
            continue
        for name, ref in refs.items():
            m = match(domain, ref)
            if m:
                matched_as, kind = m
                raw_matches.append({
                    "domain": domain,
                    "hits": hits,
                    "matched_as": matched_as,
                    "match_type": kind,
                    "source": name,
                })
                break

    # Collapse wildcard matches to the parent domain (ABP syntax). Exact
    # matches stay 1:1.
    collapsed: dict[tuple[str, str, str], dict] = {}
    for m in raw_matches:
        if m["match_type"] == "exact":
            key = ("exact", m["domain"], m["source"])
            if key not in collapsed:
                collapsed[key] = {
                    "entry": m["domain"],
                    "match_type": "exact",
                    "source": m["source"],
                    "hits": m["hits"],
                    "n_subdomains": 1,
                    "examples": [m["domain"]],
                }
            else:
                collapsed[key]["hits"] += m["hits"]
        else:
            # wildcard — bucket by (parent, source)
            key = ("wildcard", m["matched_as"], m["source"])
            if key not in collapsed:
                collapsed[key] = {
                    "entry": f"||{m['matched_as']}^",
                    "match_type": "wildcard",
                    "source": m["source"],
                    "hits": m["hits"],
                    "n_subdomains": 1,
                    "examples": [m["domain"]],
                }
            else:
                collapsed[key]["hits"] += m["hits"]
                collapsed[key]["n_subdomains"] += 1
                if len(collapsed[key]["examples"]) < 3:
                    collapsed[key]["examples"].append(m["domain"])

    candidates = sorted(collapsed.values(), key=lambda c: -c["hits"])

    # Write new-additions.txt
    with open(args.out_blocklist, "w", encoding="utf-8") as f:
        for c in candidates:
            if c["match_type"] == "exact":
                tag = f"{c['hits']} hits, {c['source']} exact"
            else:
                tag = (
                    f"{c['hits']} hits across {c['n_subdomains']} subdomains, "
                    f"{c['source']} wildcard — e.g. {c['examples'][0]}"
                )
            f.write(f"{c['entry']}    # {tag}\n")

    by_source: dict[str, list[dict]] = defaultdict(list)
    for c in candidates:
        by_source[c["source"]].append(c)

    today = datetime.date.today().isoformat()
    with open(args.out_report, "w", encoding="utf-8") as f:
        f.write(f"# Monthly blocklist eval — {today}\n\n")
        f.write(f"- Allowed domains (30d): {len(allowed)}\n")
        f.write(f"- Already blocked by this list: {len(existing)}\n")
        f.write(f"- New candidates: **{len(candidates)}**\n\n")
        if not candidates:
            f.write("No new candidates this month.\n")
            return 0
        f.write("## Top 25 by hits\n\n")
        f.write("| Entry | Hits | Subdomains | Via | Type | Example |\n")
        f.write("|---|---:|---:|---|---|---|\n")
        for c in candidates[:25]:
            ex = c["examples"][0]
            f.write(
                f"| `{c['entry']}` | {c['hits']} | {c['n_subdomains']} | {c['source']} | {c['match_type']} | `{ex}` |\n"
            )
        f.write("\n")
        f.write("## By reference source\n\n")
        for name, items in sorted(by_source.items(), key=lambda kv: -len(kv[1])):
            f.write(f"### {name} ({len(items)})\n\n")
            for c in items[:50]:
                detail = (
                    f"{c['hits']} hits"
                    if c["match_type"] == "exact"
                    else f"{c['hits']} hits across {c['n_subdomains']} subdomains (e.g. `{c['examples'][0]}`)"
                )
                f.write(f"- `{c['entry']}` — {detail}\n")
            if len(items) > 50:
                f.write(f"- …and {len(items) - 50} more\n")
            f.write("\n")
        f.write(
            "\n---\n\n*Review before merge: delete any lines from `blocklist.txt`"
            " you want to keep allowed. Pi-hole will pull the merged file on the"
            " next `pihole -g`.*\n"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
