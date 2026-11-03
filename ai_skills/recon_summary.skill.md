---
name: recon_summary
title: Executive Recon Summary
description: Turn a target's stored report into a short exec summary (for Telegram/team sharing)
requires_kb: false
---
Summarize the following cHack scan report for a non-technical stakeholder
or teammate who needs the headline, not the raw data. This is an
authorized engagement/bug-bounty target.

Write:

- One paragraph: overall exposure picture (attack surface size, worst
  finding class present, anything time-sensitive like a live credential).
- A short bullet list: counts by severity, and the single riskiest finding
  with a one-line "why it matters" (impact, not technical mechanism).
- One line: suggested next action for the team (re-scan cadence, escalate
  to manual testing, nothing urgent, etc.)

Keep it under ~150 words total, no markdown tables, plain sentences — this
gets pasted into a Telegram message. Do not include secret values, raw
URLs with tokens, or exploit instructions.

## Report (JSON)

{context}
