package vitni

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"sort"
	"strings"

	"github.com/gowebpki/jcs"
)

// RegistryKey is a public key entry in the trusted registry.
type RegistryKey struct {
	Kty    string `json:"kty"`    // "OKP" | "EC"
	Crv    string `json:"crv"`    // "Ed25519" | "P-256"
	X      string `json:"x"`      // base64url
	Y      string `json:"y"`      // base64url, EC only
	Alg    string `json:"alg"`    // "EdDSA" | "ES256"
	Status string `json:"status"` // "active" | "revoked"
}

// VerifyPolicy carries the expected-context constraints.
type VerifyPolicy struct {
	ExpectedBinding *string `json:"expected_binding"`
	ExpectedMethod  *string `json:"expected_method"`
}

// VerifyInput is the input object for the verify command.
type VerifyInput struct {
	SignedReceipt string                            `json:"signed_receipt"`
	Keys          map[string]map[string]RegistryKey `json:"keys"`
	Policy        VerifyPolicy                      `json:"policy"`
}

// algSpec is one row of the algorithm table: the key type an alg requires and
// the function that verifies a signature for it.
type algSpec struct {
	kty    string
	crv    string
	verify func(key RegistryKey, signingInput, sig []byte) bool
}

// algs is the SINGLE owner of {alg -> kty, crv, verify fn}. Step 5 (key-type
// binding), step 6 (verification) and SupportedAlgs (the declared alg set) all
// derive from it, so "algs we verify" and "algs we declare" cannot drift.
var algs = map[string]algSpec{
	"EdDSA": {kty: "OKP", crv: "Ed25519", verify: verifyEd25519},
	"ES256": {kty: "EC", crv: "P-256", verify: verifyES256},
}

// SupportedAlgs returns the algorithms Verify accepts, sorted by code point.
func SupportedAlgs() []string {
	out := make([]string, 0, len(algs))
	for a := range algs {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// header key-material claims that MUST NOT appear in the JWS header (§12).
var forbiddenHeaderKeys = []string{"jwk", "jku", "x5u", "x5c", "x5t", "x5t#S256"}

// Verify runs the §7 verification algorithm. First failing check wins, in the
// documented order. Returns (valid, reasonCode).
func Verify(in VerifyInput) (bool, string) {
	// --- Step 1: malformed ---
	segs := strings.Split(in.SignedReceipt, ".")
	if len(segs) != 3 {
		return false, "malformed"
	}
	headerBytes, err := DecodeB64URLStrict(segs[0])
	if err != nil {
		return false, "malformed"
	}
	payloadBytes, err := DecodeB64URLStrict(segs[1])
	if err != nil {
		return false, "malformed"
	}
	sigBytes, err := DecodeB64URLStrict(segs[2])
	if err != nil {
		return false, "malformed"
	}

	// header: strict text (no BOM, valid UTF-8, no lone-surrogate escape, depth
	// <= MaxDepth) that is exactly one JSON object. Duplicate keys are last-wins
	// and non-finite numbers are accepted: the header is never serialized.
	header, ok := decodeObject(headerBytes)
	if !ok {
		return false, "malformed"
	}
	// RFC 7797: b64 absent or true is fine; false or any non-boolean is malformed.
	if raw, present := header["b64"]; present {
		var b64 *bool
		if err := json.Unmarshal(raw, &b64); err != nil || b64 == nil || !*b64 {
			return false, "malformed"
		}
	}
	// payload: same strict text and exactly one object. Duplicate keys are
	// last-wins at parse and non-finite numbers are deferred: both fail step 7
	// (the re-serialization cannot equal the transmitted bytes).
	payload, ok := decodeObject(payloadBytes)
	if !ok {
		return false, "malformed"
	}
	performerID := stringClaim(payload, "performer_id")
	binding := stringClaim(payload, "binding")
	method := stringClaim(payload, "method")

	// --- Step 2: header_key_material ---
	for _, k := range forbiddenHeaderKeys {
		if _, ok := header[k]; ok {
			return false, "header_key_material"
		}
	}

	// --- Step 3: resolve key ---
	kid := stringClaim(header, "kid")
	if performerID == "" || kid == "" {
		return false, "unknown_key"
	}
	perfKeys, ok := in.Keys[performerID]
	if !ok {
		return false, "unknown_key"
	}
	key, ok := perfKeys[kid]
	if !ok {
		return false, "unknown_key"
	}

	// --- Step 4: revoked_key ---
	if key.Status == "revoked" {
		return false, "revoked_key"
	}

	// --- Step 5: alg_not_allowed ---
	headerAlg := stringClaim(header, "alg")
	if headerAlg == "" || headerAlg == "none" || headerAlg != key.Alg {
		return false, "alg_not_allowed"
	}
	// The registry key must be the key type its alg requires. An alg outside the
	// table, and a missing or null kty/crv, fail here, before any key material is
	// decoded. Runs after step 4 (a revoked key stays revoked_key) and after the
	// header/registry alg equality above.
	spec, known := algs[key.Alg]
	if !known || key.Kty != spec.kty || key.Crv != spec.crv {
		return false, "alg_not_allowed"
	}

	// --- Step 6: bad_signature ---
	// signing input is the ASCII bytes b64url(header).b64url(payload)
	signingInput := []byte(segs[0] + "." + segs[1])
	if !spec.verify(key, signingInput, sigBytes) {
		return false, "bad_signature"
	}

	// --- Step 7: non_canonical_payload ---
	// payload bytes (as transmitted) must equal JCS(parse(payload)) byte-for-byte.
	canon, err := jcs.Transform(payloadBytes)
	if err != nil {
		return false, "non_canonical_payload"
	}
	if !bytes.Equal(payloadBytes, canon) {
		return false, "non_canonical_payload"
	}

	// --- Step 8: context_mismatch ---
	if in.Policy.ExpectedBinding != nil {
		if binding != *in.Policy.ExpectedBinding {
			return false, "context_mismatch"
		}
	}
	if in.Policy.ExpectedMethod != nil {
		if method != *in.Policy.ExpectedMethod {
			return false, "context_mismatch"
		}
	}

	// --- Step 9: ok ---
	return true, "ok"
}

// decodeObject is the single entry for header and payload bytes: strict JSON
// text, then exactly one object (a JSON null or array is not an object; note
// json.Unmarshal accepts null into a map and leaves it nil).
func decodeObject(b []byte) (map[string]json.RawMessage, bool) {
	if err := ValidateJSONText(b, TextPolicy{}); err != nil {
		return nil, false
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil || m == nil {
		return nil, false
	}
	return m, true
}

// stringClaim extracts a string-valued claim from a raw-message map.
// Returns "" if absent or not a JSON string.
func stringClaim(m map[string]json.RawMessage, key string) string {
	raw, ok := m[key]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}

// verifyEd25519 decodes the registry x through the strict base64url decoder.
// Any key-material problem (alphabet, padding, trailing bits, wrong length) is
// reported as an invalid signature (`bad_signature`), never repaired. A JWS
// SEGMENT failing the same decoder is `malformed`: same decoder, different
// code at the call site.
func verifyEd25519(key RegistryKey, signingInput, sig []byte) bool {
	pub, err := DecodeB64URLStrict(key.X)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), signingInput, sig)
}

// verifyES256 verifies a JWS ES256 signature (raw R||S, 64 bytes). Registry
// coordinates use the same strict decoder and must be exactly 32 bytes.
func verifyES256(key RegistryKey, signingInput, sig []byte) bool {
	if len(sig) != 64 {
		return false
	}
	xb, err := DecodeB64URLStrict(key.X)
	if err != nil || len(xb) != 32 {
		return false
	}
	yb, err := DecodeB64URLStrict(key.Y)
	if err != nil || len(yb) != 32 {
		return false
	}
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xb),
		Y:     new(big.Int).SetBytes(yb),
	}
	// Reject points not on the curve.
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return false
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	digest := sha256.Sum256(signingInput)
	return ecdsa.Verify(pub, digest[:], r, s)
}
