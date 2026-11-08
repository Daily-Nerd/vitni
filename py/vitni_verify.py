"""vitni verify-only reference verifier (Python, standard library only).

Contract
--------
Run as `python -I py/vitni_verify.py <command>`. It reads the command's input
object from stdin (bytes) and writes exactly one line to stdout: JCS-canonical
JSON followed by LF, exit code 0 on every handled path. Nothing else goes to
stdout. A command the CLI does not know is {"error":"unsupported_command"}, no
command at all is {"error":"missing_command"}.

Declared commands: verify, jcs, digest, hashstring, receipt-id and profiles.
The commands a2a-artifact-hash, cost-canon, keygen, sign, sse-outputs-hash and
verify-chain exist in the protocol but not here: they answer
{"error":"unsupported_profile","profile":"cmd:<command>"} without reading stdin.

ES256 signatures are raw R||S, exactly 64 bytes. There is no DER path.

Importable API: verify(signed_receipt, keys=None, policy=None) returns the same
dict the CLI prints, never raises for any input.

Mapping for a caller that vendors this file: {"valid":true} is verified,
{"valid":false} is failed, any {"error":...} is unable (no judgement made).

Pin
---
Callers pin the sha256 of this file (shasum -a 256 py/vitni_verify.py), so
editing this file changes its pinned sha256 and is a release decision, not a
cleanup. The file carries no version stamp and no date for that reason, and no
formatter may rewrite it.
"""
