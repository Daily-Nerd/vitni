// vitni-verify is the Vitni conformance verifier CLI.
// Usage: vitni-verify <command> < input.json
// Output: a single line of JCS-canonical JSON to stdout, exit 0.
// On error: {"error":"<code>"} to stdout, exit 0.
package main

import (
	"crypto/ed25519"
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
)

func main() {
	if len(os.Args) < 2 {
		writeError("missing_command")
		return
	}
	command := os.Args[1]

	stdin, err := io.ReadAll(os.Stdin)
	if err != nil {
		writeError("stdin_read_error")
		return
	}

	var result json.RawMessage
	var cmdErr error

	switch command {
	case "jcs":
		result, cmdErr = runJCS(stdin)
	case "hashstring":
		result, cmdErr = runHashString(stdin)
	case "digest":
		result, cmdErr = runDigest(stdin)
	case "receipt-id":
		result, cmdErr = runReceiptID(stdin)
	case "sse-outputs-hash":
		result, cmdErr = runSSEOutputsHash(stdin)
	case "cost-canon":
		result, cmdErr = runCostCanon(stdin)
	case "verify":
		result, cmdErr = runVerify(stdin)
	case "verify-chain":
		result, cmdErr = runVerifyChain(stdin)
	case "a2a-artifact-hash":
		result, cmdErr = runA2AArtifactHash(stdin)
	case "sign":
		result, cmdErr = runSign(stdin)
	default:
		writeError("unsupported_command")
		return
	}

	if cmdErr != nil {
		writeError(errorCode(cmdErr))
		return
	}

	// The result must itself be JCS-canonical. Since we build it via
	// json.Marshal on structs with explicit field names, and Go's
	// encoding/json emits object keys in declaration order (not sorted),
	// we must pass it through jcs.Transform before printing.
	canonical, err := jcs.Transform(result)
	if err != nil {
		writeError("jcs_output_error")
		return
	}
	fmt.Fprintf(os.Stdout, "%s\n", canonical)
}

func writeError(code string) {
	// {"error":"<code>"} — keys already sorted (only one key), so safe to
	// build manually and put through JCS for byte-exactness.
	out := map[string]string{"error": code}
	b, _ := json.Marshal(out)
	canonical, _ := jcs.Transform(b)
	fmt.Fprintf(os.Stdout, "%s\n", canonical)
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
	raw, err := base64.StdEncoding.DecodeString(inp.BytesB64)
	if err != nil {
		// Try without padding
		raw, err = base64.RawStdEncoding.DecodeString(inp.BytesB64)
		if err != nil {
			return nil, err
		}
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
	rawBytes, err := base64.StdEncoding.DecodeString(inp.RawB64)
	if err != nil {
		rawBytes, err = base64.RawStdEncoding.DecodeString(inp.RawB64)
		if err != nil {
			return nil, err
		}
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

	// kid required.
	if inp.Kid == "" {
		return nil, errKidRequired
	}

	// Decode the 32-byte seed, accepting both standard and raw (unpadded) base64.
	seed, err := base64.StdEncoding.DecodeString(inp.PrivateKeyB64)
	if err != nil {
		seed, err = base64.RawStdEncoding.DecodeString(inp.PrivateKeyB64)
		if err != nil {
			return nil, errInvalidPrivateKey
		}
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
