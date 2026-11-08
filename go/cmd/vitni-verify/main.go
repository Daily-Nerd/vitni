// vitni-verify is the Vitni conformance verifier CLI.
// Usage: vitni-verify <command> < input.json
// Output: a single line of JCS-canonical JSON to stdout, exit 0.
// On error: {"error":"<code>"} to stdout, exit 0.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/Daily-Nerd/vitni/go"
	"github.com/gowebpki/jcs"
)

// CLI-input-validation sentinels for the `sign` command. These map to machine
// error codes in errorCode. They are local to the CLI because they describe
// malformed CLI input, not library-level protocol violations.
var (
	errInvalidPrivateKey = errors.New("invalid_private_key")
	errKidRequired       = errors.New("kid_required")
	errInvalidSeed       = errors.New("invalid_seed")
)

// commands is the single table of CLI commands. Resolving the command here,
// before any stdin byte is parsed, is what makes an unknown command answer
// unsupported_command whatever the stdin looks like.
var commands = map[string]func([]byte) (json.RawMessage, error){
	"jcs":               runJCS,
	"hashstring":        runHashString,
	"digest":            runDigest,
	"receipt-id":        runReceiptID,
	"sse-outputs-hash":  runSSEOutputsHash,
	"cost-canon":        runCostCanon,
	"verify":            runVerify,
	"verify-chain":      runVerifyChain,
	"a2a-artifact-hash": runA2AArtifactHash,
	"sign":              runSign,
	"keygen":            runKeygen,
}

// dupReject lists the commands whose stdin text is rejected for a duplicate
// object key anywhere in it (the commands whose value flows into JCS). Every
// other command keeps last-wins.
var dupReject = map[string]bool{"jcs": true, "receipt-id": true, "cost-canon": true}

func main() {
	if len(os.Args) < 2 {
		os.Stdout.Write(errorLine("missing_command"))
		return
	}
	stdin, err := io.ReadAll(os.Stdin)
	if err != nil {
		os.Stdout.Write(errorLine("stdin_read_error"))
		return
	}
	os.Stdout.Write(respond(os.Args[1], stdin))
}

// respond is the whole CLI pipeline after argv and stdin have been read: it
// returns the one output line (with its trailing newline). Order matters:
//
//  1. the command resolves (unknown: unsupported_command, stdin never parsed);
//  2. the stdin gate, ONCE for every command: strict UTF-8, no BOM, no
//     lone-surrogate escape, exactly one JSON value, depth <= MaxDepth, no
//     non-finite number, duplicate keys per dupReject, top level an object;
//  3. the command runs on text that has already passed the gate.
//
// Any gate violation is invalid_input, a command error and never a verdict.
func respond(command string, stdin []byte) []byte {
	run, ok := commands[command]
	if !ok {
		return errorLine("unsupported_command")
	}
	if err := vitni.ValidateJSONText(stdin, vitni.TextPolicy{
		RejectDuplicates: dupReject[command],
		RejectNonFinite:  true,
	}); err != nil {
		return errorLine("invalid_input")
	}
	if !isJSONObject(stdin) {
		return errorLine("invalid_input")
	}
	result, err := run(stdin)
	if err != nil {
		return errorLine(errorCode(err))
	}

	// The result must itself be JCS-canonical. Since we build it via
	// json.Marshal on structs with explicit field names, and Go's
	// encoding/json emits object keys in declaration order (not sorted),
	// we must pass it through jcs.Transform before printing.
	canonical, err := jcs.Transform(result)
	if err != nil {
		return errorLine("jcs_output_error")
	}
	return append(canonical, '\n')
}

// isJSONObject reports whether already-validated JSON text is one object (not
// null, an array or a scalar).
func isJSONObject(text []byte) bool {
	for _, c := range text {
		switch c {
		case ' ', '\t', '\n', '\r':
			continue
		}
		return c == '{'
	}
	return false
}

// errorLine renders {"error":"<code>"}: a single key is already sorted, so it
// is built by hand and passed through JCS for byte-exactness.
func errorLine(code string) []byte {
	b, _ := json.Marshal(map[string]string{"error": code})
	canonical, _ := jcs.Transform(b)
	return append(canonical, '\n')
}

func errorCode(err error) string {
	if errors.Is(err, vitni.ErrCostMustBeStringInt) {
		return "cost_must_be_string_int"
	}
	if errors.Is(err, vitni.ErrReceiptIDMustBeAbsent) {
		return "receipt_id_must_be_absent"
	}
	if errors.Is(err, vitni.ErrUnsupportedPart) {
		return "unsupported_part"
	}
	if errors.Is(err, errInvalidPrivateKey) {
		return "invalid_private_key"
	}
	if errors.Is(err, errKidRequired) {
		return "kid_required"
	}
	if errors.Is(err, errInvalidSeed) {
		return "invalid_seed"
	}
	return "invalid_input"
}

// -------------------------------------------------------------------
// Command implementations
// -------------------------------------------------------------------

func runJCS(stdin []byte) (json.RawMessage, error) {
	var inp struct {
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(stdin, &inp); err != nil {
		return nil, err
	}
	canon, err := vitni.JCS(inp.Value)
	if err != nil {
		return nil, err
	}
	out := struct {
		CanonicalHex string `json:"canonical_hex"`
		ByteLen      int    `json:"byte_len"`
	}{
		CanonicalHex: hex.EncodeToString(canon),
		ByteLen:      len(canon),
	}
	return json.Marshal(out)
}

func runHashString(stdin []byte) (json.RawMessage, error) {
	var inp struct {
		Algo      string `json:"algo"`
		DigestHex string `json:"digest_hex"`
	}
	if err := json.Unmarshal(stdin, &inp); err != nil {
		return nil, err
	}
	if inp.Algo != "sha2-256" {
		return nil, errors.New("unsupported algo: " + inp.Algo)
	}
	hashStr, err := vitni.HashString(inp.DigestHex)
	if err != nil {
		return nil, err
	}
	out := struct {
		Hashstr string `json:"hashstr"`
	}{Hashstr: hashStr}
	return json.Marshal(out)
}

func runDigest(stdin []byte) (json.RawMessage, error) {
	var inp struct {
		BytesB64 string `json:"bytes_b64"`
	}
	if err := json.Unmarshal(stdin, &inp); err != nil {
		return nil, err
	}
	raw, err := vitni.DecodeStdBase64(inp.BytesB64)
	if err != nil {
		return nil, err
	}
	hashStr, err := vitni.Digest(raw)
	if err != nil {
		return nil, err
	}
	out := struct {
		Hashstr string `json:"hashstr"`
	}{Hashstr: hashStr}
	return json.Marshal(out)
}

func runReceiptID(stdin []byte) (json.RawMessage, error) {
	var inp struct {
		Receipt json.RawMessage `json:"receipt"`
	}
	if err := json.Unmarshal(stdin, &inp); err != nil {
		return nil, err
	}
	canonHex, receiptID, err := vitni.ReceiptID(inp.Receipt)
	if err != nil {
		return nil, err
	}
	out := struct {
		CanonicalHex string `json:"canonical_hex"`
		ReceiptID    string `json:"receipt_id"`
	}{
		CanonicalHex: canonHex,
		ReceiptID:    receiptID,
	}
	return json.Marshal(out)
}

func runSSEOutputsHash(stdin []byte) (json.RawMessage, error) {
	var inp struct {
		RawB64 string `json:"raw_b64"`
		Mode   string `json:"mode"`
	}
	if err := json.Unmarshal(stdin, &inp); err != nil {
		return nil, err
	}
	rawBytes, err := vitni.DecodeStdBase64(inp.RawB64)
	if err != nil {
		return nil, err
	}
	decodedHex, outputsHash, err := vitni.SSEOutputsHash(rawBytes, inp.Mode)
	if err != nil {
		return nil, err
	}
	out := struct {
		DecodedHex  string `json:"decoded_hex"`
		OutputsHash string `json:"outputs_hash"`
	}{
		DecodedHex:  decodedHex,
		OutputsHash: outputsHash,
	}
	return json.Marshal(out)
}

func runCostCanon(stdin []byte) (json.RawMessage, error) {
	var inp struct {
		Cost json.RawMessage `json:"cost"`
	}
	if err := json.Unmarshal(stdin, &inp); err != nil {
		return nil, err
	}
	canon, err := vitni.CostCanon(inp.Cost)
	if err != nil {
		return nil, err
	}
	out := struct {
		CanonicalHex string `json:"canonical_hex"`
	}{CanonicalHex: hex.EncodeToString(canon)}
	return json.Marshal(out)
}

func runVerify(stdin []byte) (json.RawMessage, error) {
	var inp vitni.VerifyInput
	if err := json.Unmarshal(stdin, &inp); err != nil {
		return nil, err
	}
	valid, reason := vitni.Verify(inp)
	out := struct {
		Valid  bool   `json:"valid"`
		Reason string `json:"reason"`
	}{
		Valid:  valid,
		Reason: reason,
	}
	return json.Marshal(out)
}

func runVerifyChain(stdin []byte) (json.RawMessage, error) {
	var inp vitni.VerifyChainInput
	if err := json.Unmarshal(stdin, &inp); err != nil {
		return nil, err
	}
	valid, reason, chainLen := vitni.VerifyChain(inp)
	out := struct {
		Valid    bool   `json:"valid"`
		Reason   string `json:"reason"`
		ChainLen int    `json:"chain_len"`
	}{
		Valid:    valid,
		Reason:   reason,
		ChainLen: chainLen,
	}
	return json.Marshal(out)
}

func runA2AArtifactHash(stdin []byte) (json.RawMessage, error) {
	var inp struct {
		Artifact json.RawMessage `json:"artifact"`
	}
	if err := json.Unmarshal(stdin, &inp); err != nil {
		return nil, err
	}
	descriptorBytes, outputsHash, err := vitni.A2AArtifactHash(inp.Artifact)
	if err != nil {
		return nil, err
	}
	out := struct {
		OutputsHash   string `json:"outputs_hash"`
		DescriptorHex string `json:"descriptor_hex"`
	}{
		OutputsHash:   outputsHash,
		DescriptorHex: hex.EncodeToString(descriptorBytes),
	}
	return json.Marshal(out)
}

// runSign produces a deterministic EdDSA JWS signed receipt from a 32-byte Ed25519
// seed. private_key_b64 is the RFC 8032 seed (NOT the 64-byte expanded key) — the
// only runtime-portable form. We expand it via ed25519.NewKeyFromSeed and reuse the
// existing vitni.Sign primitive so framing matches Verify exactly.
// knownReceiptKeys is the closed set of top-level Receipt fields (§2). Anything
// else is rejected at sign time; extensions belong in `ext`.
var knownReceiptKeys = map[string]bool{
	"v": true, "binding": true, "action_ref": true, "performer_id": true,
	"requester_id": true, "method": true, "inputs_hash": true, "outputs_hash": true,
	"cost": true, "status": true, "reason": true, "parent_receipt_hash": true,
	"parent_performer_id": true, "log_policy": true, "ts": true, "nonce": true,
	"ext": true,
}

func runSign(stdin []byte) (json.RawMessage, error) {
	var inp struct {
		Receipt       json.RawMessage `json:"receipt"`
		Kid           string          `json:"kid"`
		PrivateKeyB64 string          `json:"private_key_b64"`
	}
	if err := json.Unmarshal(stdin, &inp); err != nil {
		return nil, err
	}

	// receipt must be present and a JSON object.
	if len(inp.Receipt) == 0 {
		return nil, errors.New("invalid_input: missing receipt")
	}
	var receiptObj map[string]json.RawMessage
	if err := json.Unmarshal(inp.Receipt, &receiptObj); err != nil {
		return nil, err
	}

	// receipt_id must be absent (reuse the existing contract).
	if _, present := receiptObj["receipt_id"]; present {
		return nil, vitni.ErrReceiptIDMustBeAbsent
	}

	// Reject unknown top-level keys: the Receipt is a defined object and
	// forward-compatible extensions belong in `ext`. Signing over an unknown
	// key (or silently dropping it) would let un-schema'd data affect — or
	// vanish from — the signed bytes and receipt_id. (§2)
	for k := range receiptObj {
		if !knownReceiptKeys[k] {
			return nil, fmt.Errorf("invalid_input: unknown receipt field %q", k)
		}
	}

	// kid required.
	if inp.Kid == "" {
		return nil, errKidRequired
	}

	// Decode the 32-byte seed: canonical padded or canonical unpadded base64 only.
	seed, err := vitni.DecodeStdBase64(inp.PrivateKeyB64)
	if err != nil {
		return nil, errInvalidPrivateKey
	}
	if len(seed) != ed25519.SeedSize {
		return nil, errInvalidPrivateKey
	}
	priv := ed25519.NewKeyFromSeed(seed)

	// Decode the receipt body into the typed Receipt and sign it.
	var receipt vitni.Receipt
	if err := json.Unmarshal(inp.Receipt, &receipt); err != nil {
		return nil, err
	}
	signed, err := vitni.Sign(receipt, inp.Kid, priv)
	if err != nil {
		return nil, err
	}

	out := struct {
		SignedReceipt string `json:"signed_receipt"`
	}{SignedReceipt: signed}
	return json.Marshal(out)
}

// runKeygen generates an Ed25519 keypair, or — when seed_b64 is present —
// deterministically derives the public key from the given 32-byte RFC 8032
// seed (no randomness consumed). The emitted jwk pastes verbatim into the
// keys[performer_id][kid] slot of verify input, status kept explicit so
// revocation semantics stay visible.
//
// ENCODING ASYMMETRY (deliberate): jwk.x is base64url-nopad because JWK
// (RFC 7517/8037) mandates it; private_key_b64 is standard padded base64
// because that is the form `sign` consumes. Do not normalize.
//
// A PRESENT-but-empty seed_b64 is invalid_seed, never treat-as-absent: a
// buggy consumer passing "" must not silently receive a fresh random key.
func runKeygen(stdin []byte) (json.RawMessage, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(stdin, &obj); err != nil {
		return nil, err
	}
	if obj == nil {
		return nil, errors.New("invalid_input: not an object")
	}
	for k := range obj {
		if k != "seed_b64" {
			return nil, fmt.Errorf("invalid_input: unknown field %q", k)
		}
	}

	var seed []byte
	if raw, present := obj["seed_b64"]; present {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, errInvalidSeed
		}
		var err error
		seed, err = vitni.DecodeStdBase64(s)
		if err != nil {
			return nil, errInvalidSeed
		}
		if len(seed) != ed25519.SeedSize {
			return nil, errInvalidSeed
		}
	} else {
		seed = make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, err // unreachable in practice; maps to invalid_input
		}
	}

	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	out := struct {
		Jwk struct {
			Alg    string `json:"alg"`
			Crv    string `json:"crv"`
			Kty    string `json:"kty"`
			Status string `json:"status"`
			X      string `json:"x"`
		} `json:"jwk"`
		PrivateKeyB64 string `json:"private_key_b64"`
	}{}
	out.Jwk.Alg = "EdDSA"
	out.Jwk.Crv = "Ed25519"
	out.Jwk.Kty = "OKP"
	out.Jwk.Status = "active"
	out.Jwk.X = base64.RawURLEncoding.EncodeToString(pub)
	out.PrivateKeyB64 = base64.StdEncoding.EncodeToString(seed)
	return json.Marshal(out)
}
