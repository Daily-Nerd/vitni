package vitni

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/gowebpki/jcs"
)

// Version is the Vitni protocol version string stamped into receipts.
const Version = "vitni/0.2"

// MCPMetaKey is the MCP `_meta` key under which a Vitni receipt is carried.
const MCPMetaKey = "dev.vitni/receipt"

// Cost is the cost block of a receipt. Magnitudes are decimal STRINGS (the 2^53
// defense — never JSON numbers). RailRef is an optional reference string.
type Cost struct {
	Tokens    string  `json:"tokens"`
	USDMicros string  `json:"usd_micros"`
	WallMs    string  `json:"wall_ms"`
	RailRef   *string `json:"rail_ref"`
}

// Receipt is a Vitni receipt payload (without receipt_id; that is the content
// address derived from JCS(receipt)). All nullable fields use pointers so they
// serialize as JSON null when unset.
type Receipt struct {
	V                 string  `json:"v"`
	Binding           string  `json:"binding"`
	ActionRef         *string `json:"action_ref"`
	PerformerID       string  `json:"performer_id"`
	RequesterID       *string `json:"requester_id"`
	Method            string  `json:"method"`
	InputsHash        string  `json:"inputs_hash"`
	OutputsHash       string  `json:"outputs_hash"`
	Cost              Cost    `json:"cost"`
	Status            string  `json:"status"`
	Reason            *string `json:"reason"`
	ParentReceiptHash *string `json:"parent_receipt_hash"`
	ParentPerformerID *string `json:"parent_performer_id,omitempty"`
	LogPolicy         string  `json:"log_policy"`
	Ts                string  `json:"ts"`
	Nonce             string  `json:"nonce"`
}

// Sign produces a JWS-compact signed receipt (header.payload.signature) over the
// JCS-canonical octets of the receipt, using Ed25519 (alg "EdDSA").
//
// The payload is the RFC 8785 canonical form of the receipt, so a verifier's
// non_canonical_payload check passes. The receipt's version field is forced to
// the current Version constant. The signing input is the ASCII bytes
// b64url(header).b64url(payload), matching Verify.
func Sign(r Receipt, kid string, priv ed25519.PrivateKey) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", errors.New("invalid ed25519 private key size")
	}
	if kid == "" {
		return "", errors.New("kid must not be empty")
	}

	// Stamp the protocol version.
	r.V = Version

	// Canonicalize the payload (JCS) so it round-trips with Verify step 7.
	payloadJSON, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	payloadCanon, err := jcs.Transform(payloadJSON)
	if err != nil {
		return "", err
	}

	// Canonical JWS protected header: {"alg":"EdDSA","kid":<kid>}.
	headerJSON, err := json.Marshal(map[string]string{"alg": "EdDSA", "kid": kid})
	if err != nil {
		return "", err
	}
	headerCanon, err := jcs.Transform(headerJSON)
	if err != nil {
		return "", err
	}

	headerSeg := base64.RawURLEncoding.EncodeToString(headerCanon)
	payloadSeg := base64.RawURLEncoding.EncodeToString(payloadCanon)
	signingInput := []byte(headerSeg + "." + payloadSeg)

	sig := ed25519.Sign(priv, signingInput)
	sigSeg := base64.RawURLEncoding.EncodeToString(sig)

	return headerSeg + "." + payloadSeg + "." + sigSeg, nil
}
