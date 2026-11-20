---
id: 0
type: landmine
title: A release.yml job with no if is skipped whenever any ancestor job was skipped, and the run still ends green
severity: high
confidence: 0.9
created: 2026-11-20
authors: ["claude-code"]
anchors:
  - path: .github/workflows/release.yml
evidence:
  - pr: 93
  - note: "run 44667949815: go_tag dispatch for go/v0.7.0 ended green with build-binaries and release-assets skipped"
expires:
  condition: "release.yml stops having conditionally skipped jobs (release-please, tag-go) upstream of other jobs"
  review_after: 2027-11-20
status: candidate
---

GitHub Actions gives a job with no `if:` an implicit `success()`, and that
checks EVERY ancestor in the `needs` chain, not just the direct need. In
release.yml, a `go_tag` dispatch skips `release-please` and `tag-go` by
design, so any job below them with no condition is skipped too, and the
workflow still reports success. That is how the first backfill of
go/v0.7.0 attached no binaries (issue #92, PR #93).

Every job below a skippable job must gate explicitly on its direct needs:
`if: ${{ !cancelled() && needs.<job>.result == 'success' }}`. Do not use
`always()`: it also runs after a cancel. `conformance/release-workflow.test.mjs`
enforces both rules for go-release, build-binaries and release-assets; a
new job added below tag-go needs the same gate and a line in that test.
