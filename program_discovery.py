#!/usr/bin/env python3
"""
program_discovery.py — pull public bug-bounty programs from platform feeds and
normalize them into onboarding candidates for cHack's Phase-3 auto-discovery.

NO credentials. Only public, anonymous endpoints are used:

  * YesWeHack — https://api.yeswehack.com/programs  (list, paginated) and
    /programs/{slug} (per-program scope). Full adapter: list + structured scope.
  * Bugcrowd  — https://bugcrowd.com/engagements.json (public directory list).
    LIST ONLY: per-program scope on Bugcrowd is served behind the authenticated
    hacker portal, so discovered Bugcrowd programs carry no auto-parsed scope —
    they surface as names for the operator to onboard manually (/onboard).

This module only *discovers and normalizes*. It never writes scope.txt and never
decides scope — every candidate still goes through the human approval gate. Each
candidate is a dict:
  {platform, handle, name, url, scope_raw, roe_raw, source_meta}

Usage:
  python3 program_discovery.py --platforms yeswehack,bugcrowd --limit 25
  python3 program_discovery.py --platforms yeswehack --limit 5   # prints JSON
"""

import argparse
import json
import sys
import time
import urllib.error
import urllib.request

# Generic client identifier — NEVER embed the operator's identity/email here.
_UA = "cHack-discovery/1.0 (+bug-bounty recon; contact via platform)"
_TIMEOUT = 25


def _fetch_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
            if r.status != 200:
                return None
            return json.loads(r.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, urllib.error.HTTPError, ValueError, TimeoutError):
        return None


# --------------------------------------------------------------------------
# YesWeHack — list + per-program scope (fully no-auth)
# --------------------------------------------------------------------------

# scope_type values we treat as scannable web/host assets. Everything else
# (mobile apps, source, other) is recorded in source_meta but not offered as
# scannable scope text.
_YWH_WEB_TYPES = {"web-application", "api", "ip-address", "ip-range"}


def discover_yeswehack(limit=25, pause=0.3):
    out = []
    page = 1
    max_pages = 10
    while page <= max_pages and len(out) < limit:
        data = _fetch_json(f"https://api.yeswehack.com/programs?page={page}")
        if not data or "items" not in data:
            break
        for it in data["items"]:
            if len(out) >= limit:
                break
            # Public bug-bounty programs only (skip VDP / private / unpublished).
            if not it.get("public"):
                continue
            if it.get("type") not in ("bug-bounty", None):
                continue
            slug = it.get("slug")
            if not slug:
                continue
            detail = _fetch_json(f"https://api.yeswehack.com/programs/{slug}")
            time.sleep(pause)
            scope_lines = []
            other_assets = []
            roe = ""
            if detail:
                for s in detail.get("scopes", []) or []:
                    val = (s.get("scope") or "").strip()
                    st = s.get("scope_type") or ""
                    if not val:
                        continue
                    if st in _YWH_WEB_TYPES:
                        scope_lines.append(val)
                    else:
                        other_assets.append({"scope": val, "type": st})
                # Rules-of-engagement free text, if the program exposes any.
                roe = (detail.get("rules") or detail.get("message") or "") or ""
            out.append({
                "platform": "yeswehack",
                "handle": slug,
                "name": it.get("title") or slug,
                "url": f"https://yeswehack.com/programs/{slug}",
                "scope_raw": "In scope:\n" + "\n".join(scope_lines) if scope_lines else "",
                "roe_raw": roe,
                "source_meta": {
                    "bounty": it.get("bounty"),
                    "activity_area": it.get("activity_area"),
                    "non_web_assets": other_assets,
                },
            })
        if page >= (data.get("pagination", {}).get("nb_pages") or 1):
            break
        page += 1
    return out


# --------------------------------------------------------------------------
# Bugcrowd — public directory list only (scope needs auth, so not parsed)
# --------------------------------------------------------------------------

def discover_bugcrowd(limit=25):
    out = []
    data = _fetch_json("https://bugcrowd.com/engagements.json?category=bug_bounty&sort_by=promoted&page=1")
    if not data or "engagements" not in data:
        return out
    for e in data["engagements"]:
        if len(out) >= limit:
            break
        brief = e.get("briefUrl") or ""
        handle = brief.rstrip("/").split("/")[-1] if brief else (e.get("name") or "").lower().replace(" ", "-")
        if not handle:
            continue
        out.append({
            "platform": "bugcrowd",
            "handle": handle,
            "name": e.get("name") or handle,
            "url": f"https://bugcrowd.com{brief}" if brief else "",
            # Scope is behind the authenticated portal — surfaced for manual onboarding.
            "scope_raw": "",
            "roe_raw": "",
            "source_meta": {"tagline": e.get("tagline"), "needs_manual_scope": True},
        })
    return out


_ADAPTERS = {
    "yeswehack": discover_yeswehack,
    "ywh": discover_yeswehack,
    "bugcrowd": discover_bugcrowd,
    "bc": discover_bugcrowd,
}


def discover(platforms, limit=25):
    seen = set()
    results = []
    for p in platforms:
        fn = _ADAPTERS.get(p.strip().lower())
        if not fn:
            continue
        for cand in fn(limit=limit):
            key = (cand["platform"], cand["handle"].lower())
            if key in seen:
                continue
            seen.add(key)
            results.append(cand)
    return results


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--platforms", default="yeswehack,bugcrowd")
    ap.add_argument("--limit", type=int, default=25)
    args = ap.parse_args(argv[1:])
    cands = discover([p for p in args.platforms.split(",") if p.strip()], limit=args.limit)
    print(json.dumps({"count": len(cands), "candidates": cands}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
