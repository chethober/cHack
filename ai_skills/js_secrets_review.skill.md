---
name: js_secrets_review
title: JS Secrets Review
description: Review js_secrets.py output and classify confirmed-live/candidate/noise, no payloads
requires_kb: false
---
You are reviewing output from `js_secrets.py`, cHack's JavaScript secret
scanner, for a single authorized target. Each item already carries a
tiered classification (confirmed-live / candidate / informational) from
the scanner's own entropy and vendor-pattern checks.

For the secrets/findings JSON below:

1. Sanity-check the scanner's tiering: does anything tagged "candidate" or
   "informational" look, from the surrounding evidence (variable name,
   file path, vendor prefix), like it's actually live and worth escalating
   — or does anything tagged higher look like a placeholder/test/example
   key that should be downgraded?
2. Group by credential type/provider (cloud, payment, analytics, internal
   API, etc.) and note any provider whose *read-only* verification API
   could confirm liveness without taking any write/destructive action —
   name the provider and what a read-only check would look like in plain
   English, not code.
3. Call out any secret that appears in a client-bundled file (vs.
   server-only context) as a higher-priority exposure regardless of the
   credential's own blast radius, since it's already public.
4. Produce a short remediation note per confirmed/escalated item: rotate
   credential, scope it down, move it server-side, etc.

Do not fabricate API calls, write code to exfiltrate or use any secret,
and do not output the raw secret value beyond what's already redacted in
the input. Output is for the human operator's own authorized review only.

## Secrets / findings (JSON)

{context}
