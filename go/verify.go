package vitni

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"unicode/utf8"

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
	headerBytes, err := base64.RawURLEncoding.DecodeString(segs[0])
	if err != nil {
		return false, "malformed"
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(segs[1])
	if err != nil {
		return false, "malformed"
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(segs[2])
	if err != nil {
		return false, "malformed"
	}

	// header must be valid JSON object
	var header map[string]json.RawMessage
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return false, "malformed"
	}
	// payload must be valid UTF-8 and a valid JSON object (§7 step 1: malformed).
	if !utf8.Valid(payloadBytes) {
		return false, "malformed"
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
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

	// --- Step 6: bad_signature ---
	// signing input is the ASCII bytes b64url(header).b64url(payload)
	signingInput := []byte(segs[0] + "." + segs[1])
	if !verifySignature(key, headerAlg, signingInput, sigBytes) {
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

// verifySignature dispatches to the right algorithm and verifies the signature
// over signingInput. Returns true iff the signature is valid.
func verifySignature(key RegistryKey, alg string, signingInput, sig []byte) bool {
	switch alg {
	case "EdDSA":
		pub, err := base64.RawURLEncoding.DecodeString(key.X)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return false
		}
		return ed25519.Verify(ed25519.PublicKey(pub), signingInput, sig)

	case "ES256":
		// JWS ES256 signature is raw R‖S, 64 bytes.
		if len(sig) != 64 {
			return false
		}
		xb, err := base64.RawURLEncoding.DecodeString(key.X)
		if err != nil || len(xb) != 32 {
			return false
		}
		yb, err := base64.RawURLEncoding.DecodeString(key.Y)
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

	default:
		return false
	}
}
