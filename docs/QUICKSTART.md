# Quickstart

Get from zero to a signed, independently-verifiable receipt in a few minutes.

## Install

TypeScript / Node (>= 18):

```sh
npm i @daily-nerd/vitni
```

Go (>= 1.21):

```sh
go get github.com/Daily-Nerd/vitni/go@latest   # requires go/v0.3.0+ (earlier tags declare the pre-rename module path)
go install github.com/Daily-Nerd/vitni/go/cmd/vitni-verify@latest   # CLI binary: vitni-verify
```

## Production path — co-sign an MCP tool result

In a real MCP server you co-sign each tool result with the `vitniToolResult`
middleware. It builds the Receipt (binding, method, `inputs_hash`, `outputs_hash`,
cost) and attaches the signed JWS to `result._meta["dev.veritrail/receipt"]`. A
client that ignores `_meta` is entirely unaffected — the receipt is additive.

```ts
import { generateTestSigner, vitniToolResult } from '@daily-nerd/vitni';

// In production, `signer.privateKey` comes from your key custody (KMS/HSM),
// NOT from generateTestSigner — that helper is for demos/tests only.
const signer = generateTestSigner('srv-mcp-demo', 'ed-demo-1');

// After your tool runs, co-sign its result before returning it to the client:
const result = vitniToolResult({
  signer,
  toolName: 'add',
  params: { a: 2, b: 3 },
  result: { content: [{ type: 'text', text: '5' }] },
});
// result._meta['dev.veritrail/receipt'] now holds the compact JWS receipt.
```

Verify it independently (offline) with the public key registry:

```ts
import { verify, registryFromSigner } from '@daily-nerd/vitni';

const jws = result._meta['dev.veritrail/receipt'] as string;
const verdict = verify({
  signed_receipt: jws,
  keys: registryFromSigner(signer),         // { performer_id: { kid: publicJwk } }
  policy: { expected_binding: 'mcp', expected_method: 'mcp:add' },
});
// -> { valid: true, reason: 'ok' }
```

## Local check — sign and verify with the CLI

The `vitni-verify` CLI reads one JSON object on stdin and writes one
JCS-canonical line to stdout. Pipe `sign` straight into `verify` to confirm a
round-trip locally. `sign` takes a 32-byte Ed25519 seed (RFC 8032), base64-encoded.

```sh
# A fixed demo seed (bytes 0x01..0x20) and its derived public key are used here.
SEED_B64='AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA='
PUB_X='ebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ'

RECEIPT='{"v":"veritrail/0.1","binding":"mcp","action_ref":null,"performer_id":"srv-ed","requester_id":null,"method":"mcp:echo","inputs_hash":"uEiAs8k26X7CjDiboOyrFueKeGxYeXB-nQl5zBDNik4uYJA","outputs_hash":"uEiAs8k26X7CjDiboOyrFueKeGxYeXB-nQl5zBDNik4uYJA","cost":{"tokens":"10","usd_micros":"0","wall_ms":"3","rail_ref":null},"status":"OK","reason":null,"parent_receipt_hash":null,"log_policy":"best_effort","ts":"2026-05-28T00:00:00Z","nonce":"uEiDjsMRCmPwcFJr79MiZb7kkJ65B5GSbk0yklZkbeFK4VQ"}'

# 1. sign -> a compact JWS, then 2. extract it and verify it.
JWS=$(printf '{"receipt":%s,"kid":"ed-1","private_key_b64":"%s"}' "$RECEIPT" "$SEED_B64" \
  | vitni-verify sign | node -e 'process.stdin.on("data",d=>process.stdout.write(JSON.parse(d).signed_receipt))')

printf '{"signed_receipt":"%s","keys":{"srv-ed":{"ed-1":{"kty":"OKP","crv":"Ed25519","x":"%s","alg":"EdDSA","status":"active"}}},"policy":{"expected_binding":null,"expected_method":null}}' "$JWS" "$PUB_X" \
  | vitni-verify verify
# -> {"reason":"ok","valid":true}
```

## CLI vs. library: which to use

The CLI `sign` command exists for **conformance testing and local experimentation**
— it accepts a raw private-key seed on stdin, which is convenient for reproducible
vectors but is **not** a production key-custody pattern. Production signing uses the
library middleware (`vitniToolResult` / `signReceipt`) with a `signer.privateKey`
held by your real key custody (KMS/HSM). **Never pass a production private key on
stdin.**
