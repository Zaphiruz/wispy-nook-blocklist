#!/usr/bin/env python3
"""Rank candidate domains to add to the Pi-hole blocklist.

Inputs:
  --allowed  CSV of "domain|home|work|dom|guest|control|vpn|gaming|total" from
             Pi-hole FTL (status 2/3/14, last 30d), one row per domain.
  --refs-dir directory of raw reference blocklists (any format)
  --existing current blocklist.txt (comment-stripped domains are excluded)

Outputs:
  --out-blocklist newline-separated candidates sorted desc by hits, each line
                  annotated with the matched ref, total hits, and originating
                  subnet (e.g. "work-only").
  --out-report    markdown report with top candidates grouped by matched source
                  and a dedicated "work-only" section (lower-risk blocks).
"""
from __future__ import annotations

import argparse
import datetime
import os
import re
import sys
from collections import defaultdict

DOMAIN_RE = re.compile(r"^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$")

# Subnet columns in the order emitted by LC3's pihole-export-queries.
SUBNETS = ("home", "work", "dom", "guest", "control", "vpn", "gaming")
# End-user subnets — the ones we care about for "who would notice if blocked".
# Omits `dom` (local service hosts talking to each other) and `control` (mgmt).
END_USER_SUBNETS = ("home", "work", "guest", "vpn", "gaming")


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


def load_allowed(path: str) -> list[dict]:
    """Load `domain|home|work|dom|guest|control|vpn|gaming|total` rows.

    Falls back to the old `domain|total` 2-column format so an older LC3
    export doesn't fail the eval (all per-subnet counts become 0).
    """
    rows: list[dict] = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            s = line.strip()
            if not s or "|" not in s:
                continue
            parts = s.split("|")
            domain = normalize_line(parts[0])
            if not domain:
                continue
            try:
                nums = [int(x) for x in parts[1:]]
            except ValueError:
                continue
            if len(nums) == len(SUBNETS) + 1:
                counts = dict(zip(SUBNETS, nums[:-1]))
                total = nums[-1]
            elif len(nums) == 1:
                counts = {s: 0 for s in SUBNETS}
                total = nums[0]
            else:
                continue
            rows.append({"domain": domain, "hits": total, "counts": counts})
    return rows


def subnet_tag(counts: dict[str, int]) -> str:
    """Describe who's talking to this domain. Short, for inline comments."""
    active = [s for s in END_USER_SUBNETS if counts.get(s, 0) > 0]
    if not active:
        # Only infra (dom/control) saw it, or nothing — rare since we filter on
        # total>0 upstream, so just show as "infra".
        infra = [s for s in ("dom", "control") if counts.get(s, 0) > 0]
        return "infra-only" if infra else "none"
    if len(active) == 1:
        return f"{active[0]}-only"
    user_total = sum(counts.get(s, 0) for s in END_USER_SUBNETS)
    if user_total == 0:
        return "mixed"
    dominant = max(active, key=lambda s: counts[s])
    pct = counts[dominant] * 100 // user_total
    if pct >= 90:
        return f"mostly-{dominant}"
    return "mixed"


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
    ap.add_argument("--allow-dir", default="")
    ap.add_argument("--existing", required=True)
    ap.add_argument("--out-blocklist", required=True)
    ap.add_argument("--out-report", required=True)
    ap.add_argument("--min-hits", type=int, default=1)
    args = ap.parse_args()

    allowed = load_allowed(args.allowed)
    existing = load_existing(args.existing)
    refs = load_refs(args.refs_dir)
    allowlists = load_refs(args.allow_dir) if args.allow_dir else {}
    # Flatten allowlists into one set for cheap lookup
    allow_union: set[str] = set()
    for s in allowlists.values():
        allow_union.update(s)
    print(f"allowed domains: {len(allowed)}", file=sys.stderr)
    print(f"already in blocklist.txt: {len(existing)}", file=sys.stderr)
    for name, s in refs.items():
        print(f"  ref {name}: {len(s)}", file=sys.stderr)
    for name, s in allowlists.items():
        print(f"  allow {name}: {len(s)}", file=sys.stderr)

    # Per-domain match
    raw_matches: list[dict] = []
    for row in allowed:
        if row["hits"] < args.min_hits:
            continue
        if row["domain"] in existing:
            continue
        for name, ref in refs.items():
            m = match(row["domain"], ref)
            if m:
                matched_as, kind = m
                raw_matches.append({
                    "domain": row["domain"],
                    "hits": row["hits"],
                    "counts": row["counts"],
                    "matched_as": matched_as,
                    "match_type": kind,
                    "source": name,
                })
                break

    def new_candidate(m: dict, entry: str, block_domain: str) -> dict:
        return {
            "entry": entry,
            "block_domain": block_domain,
            "match_type": m["match_type"],
            "source": m["source"],
            "hits": m["hits"],
            "counts": dict(m["counts"]),
            "n_subdomains": 1,
            "examples": [m["domain"]],
        }

    # Collapse wildcard matches to the parent domain (ABP syntax). Exact
    # matches stay 1:1. Subnet counts are summed across the collapsed set.
    collapsed: dict[tuple[str, str, str], dict] = {}
    for m in raw_matches:
        if m["match_type"] == "exact":
            key = ("exact", m["domain"], m["source"])
            if key not in collapsed:
                collapsed[key] = new_candidate(m, m["domain"], m["domain"])
            else:
                collapsed[key]["hits"] += m["hits"]
                for s in SUBNETS:
                    collapsed[key]["counts"][s] += m["counts"].get(s, 0)
        else:
            key = ("wildcard", m["matched_as"], m["source"])
            if key not in collapsed:
                collapsed[key] = new_candidate(
                    m, f"||{m['matched_as']}^", m["matched_as"]
                )
            else:
                collapsed[key]["hits"] += m["hits"]
                for s in SUBNETS:
                    collapsed[key]["counts"][s] += m["counts"].get(s, 0)
                collapsed[key]["n_subdomains"] += 1
                if len(collapsed[key]["examples"]) < 3:
                    collapsed[key]["examples"].append(m["domain"])

    for c in collapsed.values():
        c["subnet_tag"] = subnet_tag(c["counts"])

    # Annotate each candidate with any allowlist match on the domain being
    # blocked (or any parent of it).
    for c in collapsed.values():
        d = c["block_domain"]
        allow_hits: list[tuple[str, str]] = []
        parts = d.split(".")
        for i in range(len(parts) - 1):
            cur = ".".join(parts[i:])
            for name, s in allowlists.items():
                if cur in s:
                    allow_hits.append((name, cur))
        c["allow_hits"] = allow_hits

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
            tag = f"[{c['subnet_tag']}] {tag}"
            if c["allow_hits"]:
                names = ",".join(sorted({n for n, _ in c["allow_hits"]}))
                tag = f"REVIEW ({names}) — {tag}"
            f.write(f"{c['entry']}    # {tag}\n")

    by_source: dict[str, list[dict]] = defaultdict(list)
    for c in candidates:
        by_source[c["source"]].append(c)

    today = datetime.date.today().isoformat()
    work_only = [c for c in candidates if c["subnet_tag"] == "work-only"]
    with open(args.out_report, "w", encoding="utf-8") as f:
        f.write(f"# Monthly blocklist eval — {today}\n\n")
        f.write(f"- Allowed domains (30d): {len(allowed)}\n")
        f.write(f"- Already blocked by this list: {len(existing)}\n")
        flagged = [c for c in candidates if c["allow_hits"]]
        f.write(f"- New candidates: **{len(candidates)}**\n")
        f.write(f"- Only seen on the Work subnet (lower risk): **{len(work_only)}**\n")
        f.write(f"- Flagged by an allowlist (review carefully): **{len(flagged)}**\n\n")
        if not candidates:
            f.write("No new candidates this month.\n")
            return 0
        if work_only:
            f.write("## 🟢 Work-only candidates — lower risk\n\n")
            f.write("These were only queried from the Work subnet (192.168.30.0/24). Blocking them won't affect Home/Guest/VPN/Gaming devices.\n\n")
            f.write("| Entry | Work hits | Via | Example |\n")
            f.write("|---|---:|---|---|\n")
            for c in sorted(work_only, key=lambda c: -c["hits"]):
                f.write(f"| `{c['entry']}` | {c['counts']['work']} | {c['source']} | `{c['examples'][0]}` |\n")
            f.write("\n")
        if flagged:
            f.write("## ⚠ Allowlist-flagged — review before merging\n\n")
            f.write("These matched a reference allowlist and may break something if blocked.\n\n")
            f.write("| Entry | Hits | Flagged by | Subnets | Example |\n")
            f.write("|---|---:|---|---|---|\n")
            for c in flagged:
                names = ",".join(sorted({n for n, _ in c["allow_hits"]}))
                f.write(f"| `{c['entry']}` | {c['hits']} | {names} | {c['subnet_tag']} | `{c['examples'][0]}` |\n")
            f.write("\n")
        f.write("## Top 25 by hits\n\n")
        f.write("| Entry | Hits | Subnets | home | work | guest | vpn | Via | Example | Flags |\n")
        f.write("|---|---:|---|---:|---:|---:|---:|---|---|---|\n")
        for c in candidates[:25]:
            ex = c["examples"][0]
            cc = c["counts"]
            flags = []
            if c["subnet_tag"] == "work-only":
                flags.append("🟢work")
            if c["allow_hits"]:
                flags.append("⚠fp")
            f.write(
                f"| `{c['entry']}` | {c['hits']} | {c['subnet_tag']} | "
                f"{cc['home']} | {cc['work']} | {cc['guest']} | {cc['vpn']} | "
                f"{c['source']} | `{ex}` | {' '.join(flags)} |\n"
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
