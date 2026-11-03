---
name: kb_crossref
title: Knowledge-Base Cross-Reference
description: Map each finding's vuln class to your own KB checklist and flag unverified checklist items
requires_kb: true
---
You are cross-referencing a target's findings against the human analyst's
own personal methodology notes (their knowledge-base repo). You are not
being asked for exploit payloads — the KB's own payload sheets already
hold those; your job is purely to connect "what the scanner found" to
"what the analyst's own checklist says to verify next."

For each distinct vulnerability class present in the findings below:

1. Name the matching knowledge-base note (from "Knowledge base context").
2. From that note's testing checklist, list the 2-4 checklist items most
   relevant to THIS specific finding (its URL/parameter/context) that are
   not yet obviously confirmed by the scanner's own evidence.
3. Note any related vulnerability class the KB note cross-links (e.g. XSS
   note links CSRF/CORS/Clickjacking) that's worth a quick look on the
   same target even if the scanner didn't flag it directly.

If a finding's vuln class has no matching KB note in the context provided,
say so plainly instead of guessing.

## Findings (JSON)

{context}

## Knowledge base context (your own methodology notes)

{kb_context}
