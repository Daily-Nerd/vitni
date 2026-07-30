// Package vitni implements the byte-source layer of the Vitni protocol
// (§3–§5, §4.3 of the design draft). It provides deterministic, byte-exact
// functions that the CLI wraps.
package vitni

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/gowebpki/jcs"
)

// ErrCostMustBeStringInt is returned when a cost magnitude is a JSON number.
var ErrCostMustBeStringInt = errors.New("cost_must_be_string_int")

// ErrReceiptIDMustBeAbsent is returned when the receipt already has a receipt_id.
var ErrReceiptIDMustBeAbsent = errors.New("receipt_id_must_be_absent")

// JCS returns the RFC 8785 canonical UTF-8 bytes of v (any JSON value).
// It delegates to github.com/gowebpki/jcs which implements the spec correctly:
// keys sorted lexicographically, numbers per ECMAScript, no Unicode normalization.
func JCS(v json.RawMessage) ([]byte, error) {
	return jcs.Transform(v)
}

// HashString computes the pinned hash-string for a raw SHA-256 digest.
// Format: "u" + base64url-nopad( 0x12 ‖ 0x20 ‖ digestBytes )
// 0x12 = varint multihash code for sha2-256
// 0x20 = varint length 32
func HashString(digestHex string) (string, error) {
	digest, err := hex.DecodeString(digestHex)
	if err != nil {
		return "", err
	}
	return hashStringFromBytes(digest), nil
}

// hashStringFromBytes is the internal version that works directly with bytes.
func hashStringFromBytes(digest []byte) string {
	// multihash: varint(0x12) || varint(0x20) || digest
	mh := make([]byte, 2+len(digest))
	mh[0] = 0x12
	mh[1] = 0x20
	copy(mh[2:], digest)
	return "u" + base64.RawURLEncoding.EncodeToString(mh)
}

// Digest computes sha2-256 over raw bytes and returns the pinned hash-string.
func Digest(raw []byte) (string, error) {
	h := sha256.Sum256(raw)
	return hashStringFromBytes(h[:]), nil
}

// DecodeStdBase64 decodes a standard-alphabet base64 string, accepting exactly
// two forms: canonical padded (StdEncoding) or canonical unpadded
// (RawStdEncoding). Everything non-canonical — embedded newlines, excess or
// misplaced padding, non-zero trailing bits — is rejected, keeping the accept
// set byte-identical with the TS reference (decodeStdBase64). The explicit
// newline check exists because encoding/base64 silently skips \r and \n even
// under Strict(), which only enforces the trailing-bit rule.
func DecodeStdBase64(s string) ([]byte, error) {
	if strings.ContainsAny(s, "\r\n") {
		return nil, errors.New("non-canonical base64: embedded newline")
	}
	if raw, err := base64.StdEncoding.Strict().DecodeString(s); err == nil {
		return raw, nil
	}
	return base64.RawStdEncoding.Strict().DecodeString(s)
}

// ReceiptID derives the content address of a Receipt object.
// It returns (canonicalHex, receiptID, error).
// Returns ErrReceiptIDMustBeAbsent if the receipt contains a "receipt_id" key.
func ReceiptID(receipt json.RawMessage) (string, string, error) {
	// Check for receipt_id key in the raw JSON using a generic map decode.
	// We must detect the key even if the value is null.
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(receipt, &probe); err != nil {
		return "", "", err
	}
	if _, ok := probe["receipt_id"]; ok {
		return "", "", ErrReceiptIDMustBeAbsent
	}

	canon, err := jcs.Transform(receipt)
	if err != nil {
		return "", "", err
	}
	canonHex := hex.EncodeToString(canon)

	h := sha256.Sum256(canon)
	receiptID := hashStringFromBytes(h[:])
	return canonHex, receiptID, nil
}

// SSEDecode parses a raw SSE byte stream per WHATWG §9.2 and returns the
// dispatched message data strings in order.
//
// Rules implemented:
//   - Strip a single leading UTF-8 BOM (EF BB BF) if present.
//   - Normalize line terminators: \r\n, lone \r, lone \n all delimit lines.
//   - data: field value = text after "data:" and one optional leading space.
//   - Multiple data: lines in one event join with "\n" (no trailing "\n").
//   - Ignore comment lines (starting with ':') and event:/id:/retry: fields.
//   - Dispatch event on blank line; event with empty data NOT dispatched.
//   - Trailing event with no blank line NOT dispatched.
func SSEDecode(raw []byte) ([]string, error) {
	// 1. Strip single leading BOM
	if bytes.HasPrefix(raw, []byte{0xEF, 0xBB, 0xBF}) {
		raw = raw[3:]
	}

	// 2. Split into lines, normalizing \r\n, \r, \n
	lines := splitLines(raw)

	// 3. Parse events
	var messages []string
	var dataBuf []string

	for _, line := range lines {
		if line == "" {
			// Blank line: dispatch event if data is non-empty
			if len(dataBuf) > 0 {
				data := strings.Join(dataBuf, "\n")
				messages = append(messages, data)
				dataBuf = nil
			}
			continue
		}

		// Determine field name and value
		if strings.HasPrefix(line, ":") {
			// Comment line: ignore
			continue
		}

		var field, value string
		if idx := strings.IndexByte(line, ':'); idx >= 0 {
			field = line[:idx]
			rest := line[idx+1:]
			// Strip one optional leading space
			if len(rest) > 0 && rest[0] == ' ' {
				rest = rest[1:]
			}
			value = rest
		} else {
			// No colon: field name is entire line, value is empty string
			field = line
			value = ""
		}

		switch field {
		case "data":
			dataBuf = append(dataBuf, value)
		case "event", "id", "retry":
			// Ignore per spec
		}
	}
	// Trailing event with no blank line: NOT dispatched (no action needed)

	return messages, nil
}

// splitLines splits a byte slice into lines, normalizing \r\n, lone \r,
// and lone \n to produce string slices (without the terminators).
func splitLines(data []byte) []string {
	var lines []string
	start := 0
	for i := 0; i < len(data); {
		b := data[i]
		if b == '\r' {
			lines = append(lines, string(data[start:i]))
			if i+1 < len(data) && data[i+1] == '\n' {
				i += 2
			} else {
				i++
			}
			start = i
		} else if b == '\n' {
			lines = append(lines, string(data[start:i]))
			i++
			start = i
		} else {
			i++
		}
	}
	// Trailing content with no terminator is not a complete line per SSE spec.
	// (A trailing event without a blank line is not dispatched.)
	// We do NOT append data[start:] as a line if no terminator follows.
	return lines
}

// SSEOutputsHash decodes a raw SSE byte stream and returns:
//   - decodedHex: hex of the committed bytes
//   - outputsHash: pinned hash-string of the committed bytes
//
// mode must be "sse" or "sse-jsonrpc".
func SSEOutputsHash(raw []byte, mode string) (string, string, error) {
	messages, err := SSEDecode(raw)
	if err != nil {
		return "", "", err
	}

	var committed []byte
	switch mode {
	case "sse":
		// committed = UTF8( join(message_data_strings, "\n") )
		joined := strings.Join(messages, "\n")
		committed = []byte(joined)

	case "sse-jsonrpc":
		// Each message data is a JSON-RPC message.
		// Extract the inner `result` value, JCS it, join with "\n".
		var parts [][]byte
		for _, msg := range messages {
			var rpc map[string]json.RawMessage
			if err := json.Unmarshal([]byte(msg), &rpc); err != nil {
				// Skip malformed messages
				continue
			}
			result, ok := rpc["result"]
			if !ok {
				continue
			}
			canon, err := jcs.Transform(result)
			if err != nil {
				return "", "", err
			}
			parts = append(parts, canon)
		}
		committed = bytes.Join(parts, []byte("\n"))

	default:
		return "", "", errors.New("unsupported mode: " + mode)
	}

	hashStr, err := Digest(committed)
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(committed), hashStr, nil
}

// CostCanon validates that tokens, usd_micros, and wall_ms are JSON strings
// (not numbers), then returns the JCS bytes of the cost object.
// Returns ErrCostMustBeStringInt if any magnitude is a JSON number.
func CostCanon(cost json.RawMessage) ([]byte, error) {
	// Use a generic map to detect number vs string for magnitude fields
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(cost, &probe); err != nil {
		return nil, err
	}

	for _, field := range []string{"tokens", "usd_micros", "wall_ms"} {
		raw, ok := probe[field]
		if !ok {
			continue
		}
		// A JSON string starts with '"'; a number starts with a digit or '-'
		trimmed := bytes.TrimSpace(raw)
		if len(trimmed) == 0 {
			continue
		}
		if trimmed[0] != '"' {
			return nil, ErrCostMustBeStringInt
		}
	}

	return jcs.Transform(cost)
}
