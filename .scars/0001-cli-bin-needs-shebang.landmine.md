---
id: 1
type: landmine
title: ts/src/cli.ts must keep its #!/usr/bin/env node shebang on line 1 — the npm bin breaks without it
severity: high
confidence: 0.95
created: 2026-06-12
authors: ["claude-code", "Kibukx"]
anchors:
  - path: ts/src/cli.ts
  - path: ts/test/cli-bin.test.mjs
evidence:
  - note: Published @daily-nerd/veritrail@0.1.1 + 0.2.0 shipped with no shebang; running the installed bin gave 'syntax error near unexpected token <' / ENOEXEC. Fixed in 0.2.1.
expires:
  condition: "the bin is invoked only via an explicit `node dist/cli.js` wrapper, never as a bare `vitni-verify` executable"
  review_after: 2027-06-12
status: active
---

The npm `bin` maps `vitni-verify` -> `dist/cli.js`, which the OS executes
directly. Without `#!/usr/bin/env node` as the FIRST line of `ts/src/cli.ts`
(tsc preserves a leading shebang into `dist/cli.js`), the shell runs the JS as a
shell script and dies: `syntax error near unexpected token '<'` (from the JSDoc
`<command>`), or `ENOEXEC` when spawned. README/QUICKSTART tell users to run
`vitni-verify sign`, so this breaks the documented entrypoint entirely.

Why it stayed hidden through two releases: every test (vectors, mcp/a2a
roundtrip) either imports the module or invokes `node dist/cli.js` — both bypass
the bin shim, so the missing shebang never surfaced. It only appears when you run
the actually-installed binary (`node_modules/.bin/vitni-verify`).

Future editor: do NOT remove the shebang, and do NOT let a build step (banner,
license header injection, bundler) push another line above it. `ts/test/cli-bin.test.mjs`
guards this — it asserts line 1 is the shebang AND execs the bin directly. If you
add a second CLI entrypoint, give it a shebang too and a matching exec test.
