#!/usr/bin/env python3
"""
scope_parser.py — normalize a bug-bounty program's raw scope text into cHack's
`scope.txt` grammar, and flag anything a human must decide before it is trusted.

This is the single highest-risk unit in the autonomous-onboarding pipeline: a
mis-parse means scanning a host the program never authorized. It therefore
*proposes* only — it never writes `scope.txt`, never expands a wildcard into
concrete hosts, and marks every ambiguous asset for the Telegram approval gate
rather than silently emitting it.

Design rules (do not weaken without updating the onboarding gate):
  * Exact hosts / IPs / CIDRs that are clearly in scope  -> emit to scope.txt.
  * Wildcards (`*.example.com`)                           -> NEVER emit; gate.
  * Out-of-scope / exclusion lines                        -> NEVER emit; record.
  * Non-web assets (mobile apps, source, binaries, APIs
    described as docs)                                    -> record, don't emit.
  * Rules-of-engagement red flags ("no automated scanning",
    brute force, DoS, rate caps)                          -> record as roe_flags.

Pure stdlib. Importable as `parse_scope(scope_text, roe_text="")` or runnable:
    python3 scope_parser.py <file>                 # parse a file, print JSON
    python3 scope_parser.py --selftest             # run built-in fixtures
    cat scope.md | python3 scope_parser.py -       # parse stdin
"""

import ipaddress
import json
import re
import sys

# --------------------------------------------------------------------------
# Classification vocabulary
# --------------------------------------------------------------------------

# Section headers / inline markers that flip subsequent (or same) lines to
# out-of-scope. Matched case-insensitively against a cleaned line.
_OOS_HEADERS = re.compile(
    r"\b(out[\s\-]?of[\s\-]?scope|not\s+in\s+scope|excluded|exclusions?|"
    r"do\s+not\s+test|prohibited\s+targets?)\b",
    re.I,
)
_INSCOPE_HEADERS = re.compile(
    r"\b(in[\s\-]?scope|scope|targets?|assets?|domains?)\b", re.I
)

# Per-line exclusion cues (line is an exclusion even inside an in-scope block).
_LINE_EXCLUDE = re.compile(r"^\s*(!|-\s*excl|except\b|excluding\b)", re.I)
_INLINE_EXCLUDE = re.compile(
    r"\b(is\s+)?(out\s+of\s+scope|not\s+in\s+scope|excluded|off[\s\-]limits)\b", re.I
)

# "Any subdomain not explicitly listed is out of scope" — the Vinted pattern.
# When present, a bare wildcard for that apex must NOT be trusted.
_NO_IMPLICIT_WILDCARD = re.compile(
    r"\bany\s+subdomain(s)?\s+not\s+(explicitly\s+)?listed\b.*\bout\s+of\s+scope\b",
    re.I,
)

# Non-web asset cues — recorded but never emitted into a host/IP scope file.
_NONWEB = re.compile(
    r"\b(android|ios|apk|ipa|mobile\s+app(lication)?|play\.google|apps\.apple|"
    r"itunes\.apple|github\.com/|gitlab\.com/|source\s+code|binary|executable|"
    r"smart\s+contract|0x[0-9a-fA-F]{6,})\b",
    re.I,
)

# Rules-of-engagement red flags. Each (label, pattern).
_ROE_FLAGS = [
    ("no_automated_scanning", re.compile(r"\bno\b[^.\n]{0,30}\b(automat\w+|scanner|scanning)\b", re.I)),
    ("no_automated_scanning", re.compile(r"\bautomated\s+(tools?|scann\w+)[^.\n]{0,20}\b(not\s+allowed|prohibited|forbidden|disallow\w*)\b", re.I)),
    ("no_scanners", re.compile(r"\b(do\s+not|don'?t|avoid)\b[^.\n]{0,30}\bscanner", re.I)),
    ("no_brute_force", re.compile(r"\bbrute[\s\-]?forc\w*\b", re.I)),
    ("no_dos", re.compile(r"\b(denial[\s\-]of[\s\-]service|\bdos\b|ddos|load\s+test\w*|stress\s+test\w*)\b", re.I)),
    ("no_fuzzing", re.compile(r"\b(no|avoid|not)\b[^.\n]{0,20}\bfuzz\w*\b", re.I)),
    ("rate_limited", re.compile(r"\b(rate[\s\-]?limit\w*|requests?\s+per\s+second|req/s|throttl\w+)\b", re.I)),
    ("no_social_engineering", re.compile(r"\bsocial\s+engineer\w*\b", re.I)),
    ("no_physical", re.compile(r"\bphysical\s+(attack|access|security|testing)\b", re.I)),
]

# A conservative hostname matcher: labels + a TLD of >=2 alpha chars.
_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_*](-?[a-z0-9_])*\.)+[a-z]{2,63}$")

# Characters that frequently wrap a token in markdown / prose. NOTE: '*' is
# deliberately NOT here — a leading '*.' is a wildcard we must preserve, and a
# markdown bullet '*' is a separate whitespace-split token that cleans to empty.
_STRIP_WRAP = " \t\r\n`<>()[]{}\"',;|"


def _clean_token(tok):
    """Strip markdown/prose wrappers, a URL scheme, a path, and a port.

    IP/CIDR tokens are returned intact (the path-split must not eat a /24).
    """
    t = tok.strip().strip(_STRIP_WRAP).strip()
    if not t:
        return ""
    # Drop a scheme.
    t = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", t, flags=re.I)
    # Drop userinfo@.
    t = re.sub(r"^[^/@\s]+@", "", t)
    # Preserve an IP or CIDR verbatim before any path splitting.
    probe = t.strip("[]").lower()
    try:
        ipaddress.ip_network(probe, strict=False)
        return probe
    except ValueError:
        pass
    # Cut at first path / query / space (safe now: not an IP/CIDR).
    t = re.split(r"[/\s?#]", t, maxsplit=1)[0]
    # Strip a :port but keep IPv6 colons (handled separately).
    if t.count(":") == 1 and not t.startswith("["):
        host, _, port = t.partition(":")
        if port.isdigit():
            t = host
    t = t.strip(_STRIP_WRAP).lower()
    return t


def _classify(token):
    """Return (kind, value) for a cleaned token, or (None, None) if not an asset.

    kind in: host | wildcard | ip | cidr
    """
    if not token:
        return None, None

    # CIDR?
    if "/" in token:
        try:
            net = ipaddress.ip_network(token, strict=False)
            return "cidr", str(net)
        except ValueError:
            return None, None

    # IP literal?
    try:
        ipaddress.ip_address(token.strip("[]"))
        return "ip", token.strip("[]")
    except ValueError:
        pass

    # Wildcard host?
    if token.startswith("*.") or token.startswith("%."):
        base = token[2:]
        if _HOST_RE.match(base):
            return "wildcard", base
        return None, None

    # Bare apex marked wildcard elsewhere is handled by caller; plain host here.
    if _HOST_RE.match(token):
        return "host", token

    return None, None


def parse_scope(scope_text, roe_text=""):
    """Parse raw program scope (+ optional RoE text) into a structured proposal.

    Returns a dict:
      {
        assets: [ {raw, kind, value, in_scope, emit, reason} ],
        scope_txt_lines: [str],   # safe to append to scope.txt
        wildcards:   [str],       # bases a human must approve
        exclusions:  [str],
        non_web:     [str],
        roe_flags:   [str],
        needs_review: bool,       # True if wildcards / roe flags / nothing emittable
        stats: {...}
      }
    """
    scope_text = scope_text or ""
    roe_text = roe_text or ""
    combined = scope_text + "\n" + roe_text

    no_implicit_wildcard = bool(_NO_IMPLICIT_WILDCARD.search(combined))

    assets = []
    seen_emit = set()
    scope_txt_lines = []
    wildcards = []
    exclusions = []
    non_web = []

    # Track the current section's scope polarity as we walk lines.
    section_excluded = False

    for raw_line in scope_text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped:
            continue

        # Section header detection flips polarity (a header is usually its own
        # short line, not an asset line).
        header_like = len(stripped) <= 60 and not re.search(r"[0-9a-z]\.[a-z]{2,}", stripped, re.I)
        if _OOS_HEADERS.search(stripped) and (header_like or stripped.endswith(":")):
            section_excluded = True
            continue
        if _INSCOPE_HEADERS.search(stripped) and (header_like or stripped.endswith(":")) and not _OOS_HEADERS.search(stripped):
            section_excluded = False
            continue

        line_excluded = (
            section_excluded
            or bool(_LINE_EXCLUDE.search(stripped))
            or bool(_INLINE_EXCLUDE.search(stripped))
        )
        line_nonweb = bool(_NONWEB.search(stripped))

        # Pull candidate tokens out of the line (space / comma separated).
        for tok in re.split(r"[\s,]+", stripped):
            cleaned = _clean_token(tok)
            if not cleaned:
                continue
            kind, value = _classify(cleaned)
            if not kind:
                continue

            reason = ""
            in_scope = not line_excluded
            emit = False

            if line_nonweb:
                emit = False
                in_scope = False
                reason = "non-web asset (recorded, not scanned)"
                non_web.append(value)
            elif line_excluded:
                emit = False
                reason = "marked out of scope"
                exclusions.append(value)
            elif kind == "wildcard":
                emit = False  # NEVER auto-emit a wildcard.
                reason = "wildcard — requires human approval"
                wildcards.append(value)
            else:  # host / ip / cidr, in scope, web
                emit = True
                reason = "in scope"
                if value not in seen_emit:
                    seen_emit.add(value)
                    scope_txt_lines.append(value)

            assets.append({
                "raw": tok.strip(),
                "kind": kind,
                "value": value,
                "in_scope": in_scope,
                "emit": emit,
                "reason": reason,
            })

    roe_flags = sorted({label for label, pat in _ROE_FLAGS if pat.search(combined)})

    needs_review = bool(wildcards) or bool(roe_flags) or (no_implicit_wildcard and bool(wildcards)) or not scope_txt_lines

    return {
        "assets": assets,
        "scope_txt_lines": scope_txt_lines,
        "wildcards": sorted(set(wildcards)),
        "exclusions": sorted(set(exclusions)),
        "non_web": sorted(set(non_web)),
        "roe_flags": roe_flags,
        "no_implicit_wildcard": no_implicit_wildcard,
        "needs_review": needs_review,
        "stats": {
            "emit_count": len(scope_txt_lines),
            "wildcard_count": len(set(wildcards)),
            "exclusion_count": len(set(exclusions)),
            "non_web_count": len(set(non_web)),
            "roe_flag_count": len(roe_flags),
        },
    }


# --------------------------------------------------------------------------
# Self-test fixtures (real-world-shaped scope text)
# --------------------------------------------------------------------------

_FIXTURES = [
    {
        "name": "vinted-style exact hosts, no implicit wildcard",
        "scope": (
            "In scope:\n"
            "www.vinted.com\n"
            "www.vinted.net\n"
            "sandbox.vintedgo.com\n"
            "Any subdomain not explicitly listed is out of scope.\n"
            "Out of scope:\n"
            "*.vinted.com\n"
        ),
        "roe": "Please respect rate limits. No denial of service testing.",
        "expect": {
            "emit_has": ["www.vinted.com", "www.vinted.net", "sandbox.vintedgo.com"],
            "emit_missing": ["vinted.com"],
            "wildcards_empty_or_excluded": True,
            "roe_has": ["no_dos", "rate_limited"],
            "no_implicit_wildcard": True,
        },
    },
    {
        "name": "wildcard program — must gate, never emit",
        "scope": "In scope:\n*.example.com\napi.example.com\n",
        "roe": "",
        "expect": {
            "emit_has": ["api.example.com"],
            "emit_missing": ["example.com"],
            "wildcard_has": ["example.com"],
            "needs_review": True,
        },
    },
    {
        "name": "mixed assets with CIDR, IP, mobile app",
        "scope": (
            "Targets:\n"
            "- app.target.io\n"
            "- 203.0.113.0/24\n"
            "- 198.51.100.7\n"
            "- com.target.android (Android app)\n"
            "- https://docs.target.io/api endpoint\n"
        ),
        "roe": "Automated scanning is not allowed on production.",
        "expect": {
            "emit_has": ["app.target.io", "203.0.113.0/24", "198.51.100.7", "docs.target.io"],
            "roe_has": ["no_automated_scanning"],
        },
    },
]


def _selftest():
    ok = True
    for fx in _FIXTURES:
        res = parse_scope(fx["scope"], fx["roe"])
        emit = set(res["scope_txt_lines"])
        exp = fx["expect"]
        problems = []
        for h in exp.get("emit_has", []):
            if h not in emit:
                problems.append(f"missing emit: {h}")
        for h in exp.get("emit_missing", []):
            if h in emit:
                problems.append(f"should NOT emit: {h}")
        for w in exp.get("wildcard_has", []):
            if w not in res["wildcards"]:
                problems.append(f"missing wildcard flag: {w}")
        for r in exp.get("roe_has", []):
            if r not in res["roe_flags"]:
                problems.append(f"missing roe flag: {r} (got {res['roe_flags']})")
        if "needs_review" in exp and res["needs_review"] != exp["needs_review"]:
            problems.append(f"needs_review={res['needs_review']} expected {exp['needs_review']}")
        if "no_implicit_wildcard" in exp and res["no_implicit_wildcard"] != exp["no_implicit_wildcard"]:
            problems.append("no_implicit_wildcard mismatch")
        # A wildcard must never leak into emittable lines.
        for w in res["wildcards"]:
            if w in emit:
                problems.append(f"wildcard leaked into scope.txt: {w}")
        status = "PASS" if not problems else "FAIL"
        if problems:
            ok = False
        print(f"[{status}] {fx['name']}")
        for p in problems:
            print(f"         - {p}")
    print("\nSELFTEST:", "ALL PASS" if ok else "FAILURES")
    return 0 if ok else 1


def main(argv):
    if len(argv) >= 2 and argv[1] == "--selftest":
        return _selftest()
    if len(argv) < 2:
        sys.stderr.write(__doc__)
        return 2
    src = argv[1]
    if src == "-":
        scope_text = sys.stdin.read()
    else:
        with open(src, "r", encoding="utf-8", errors="replace") as f:
            scope_text = f.read()
    roe_text = ""
    if len(argv) >= 3 and argv[2] not in ("", "-"):
        with open(argv[2], "r", encoding="utf-8", errors="replace") as f:
            roe_text = f.read()
    print(json.dumps(parse_scope(scope_text, roe_text), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
