---
id: 2
type: deadend
title: npm view 404 does not mean a package name is claimable — typosquat guard rejects at publish time
severity: medium
confidence: 0.9
created: 2026-07-08
authors: ["claude-code", "Kibukx"]
anchors:
  - path: ts/package.json
  - pattern: "npm publish"
evidence:
  - note: 2026-07-08 rename session: `npm view vitni` returned E404 (free), availability recorded in vault; real `npm publish` of a placeholder then failed E403 'Package name too similar to existing packages vite,ini,jiti'
expires:
  condition: "npm drops or changes its package-name similarity (typosquat) guard"
  review_after: 2027-07-08
status: active
---

We verified the new project name `vitni` as "free on npm" via `npm view vitni`
(E404) and recorded availability as confirmed. The actual publish of a
placeholder was then rejected with E403: the registry's typosquat guard blocks
names too similar to popular packages (vite, ini, jiti) — for ALL publishers,
at publish time only. No query API surfaces this in advance. Consequence cut
both ways: the unscoped name is unclaimable by us AND by squatters, so scoped
`@daily-nerd/vitni` is the only identity and needs no defensive placeholder.
Future name checks: `npm view` proves only non-existence; the similarity guard
is only testable by an actual publish attempt (or accept scoped-only from the
start). Do not record "npm availability verified" from a 404 alone.
