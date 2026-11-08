package vitni

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strconv"
	"unicode/utf8"

	"github.com/gowebpki/jcs"
)

// ErrNotStrictB64URL reports input outside the one accepted base64url form.
var ErrNotStrictB64URL = errors.New("vitni: not strict unpadded base64url")

// DecodeB64URLStrict is the single base64url decoder for every external byte
// string: JWS segments and registry key coordinates alike.
//
// It accepts exactly one encoding per byte string: the alphabet A-Za-z0-9-_
// only, no padding, no whitespace, length never 1 mod 4, and all trailing bits
// zero. encoding/base64 on its own silently skips CR and LF and (without
// Strict) ignores non-zero trailing bits, so the alphabet is checked first and
// the stdlib decoder runs in strict mode afterwards.
//
// The decoder only decides acceptance. The call site picks the error code:
// a failing JWS segment is `malformed`, a failing registry key is
// `bad_signature`.
func DecodeB64URLStrict(s string) ([]byte, error) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return nil, ErrNotStrictB64URL
		}
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, ErrNotStrictB64URL
	}
	return b, nil
}

// MaxDepth is the pinned JSON nesting limit (DESIGN.md section 12 step 1). The
// top-level value is depth 1, every nested object or array adds one. Host
// parsers disagree (Go 10000, V8 stack overflow, CPython lower), so the limit
// is part of the protocol instead of an accident of the runtime.
const MaxDepth = 128

// ErrNotStrictJSON reports JSON text outside the strict policy.
var ErrNotStrictJSON = errors.New("vitni: JSON text violates the strict input policy")

// TextPolicy selects the per-site options of ValidateJSONText. The base rules
// (UTF-8, no BOM, no lone-surrogate escape, one value, depth <= MaxDepth)
// always apply.
type TextPolicy struct {
	RejectDuplicates bool // duplicate object keys anywhere in the text
	RejectNonFinite  bool // any number that overflows float64 to +-Inf
}

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// ValidateJSONText is the single owner of JSON text policy. It checks, in order:
// no BOM, valid UTF-8, syntactically valid JSON with nothing after the first
// value, one raw byte scan (nesting depth and lone-surrogate escapes), then, if
// the policy asks, a token walk for duplicate keys and non-finite numbers.
//
// The raw scan is needed because encoding/json turns "\ud800" into U+FFFD
// without an error, so a lone surrogate cannot be seen after decoding.
//
// It does not require the top-level value to be an object; callers decode into
// an object type and map that failure themselves.
func ValidateJSONText(b []byte, p TextPolicy) error {
	if bytes.HasPrefix(b, utf8BOM) || !utf8.Valid(b) || !json.Valid(b) {
		return ErrNotStrictJSON
	}
	if err := scanText(b, MaxDepth); err != nil {
		return err
	}
	if p.RejectDuplicates || p.RejectNonFinite {
		return walkTokens(b, p)
	}
	return nil
}

// hex4 reads the four hex digits of a \u escape. json.Valid has already run on
// every caller's input, so the digits are guaranteed to be there and valid.
func hex4(b []byte) rune {
	var r rune
	for _, c := range b[:4] {
		var d byte
		switch {
		case c >= '0' && c <= '9':
			d = c - '0'
		case c >= 'a' && c <= 'f':
			d = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			d = c - 'A' + 10
		}
		r = r<<4 | rune(d)
	}
	return r
}

// scanText walks syntactically valid JSON once, tracking string state, to
// enforce maxDepth (0 means unlimited) and reject lone-surrogate \u escapes.
func scanText(b []byte, maxDepth int) error {
	depth := 0
	inString := false
	for i := 0; i < len(b); {
		c := b[i]
		if !inString {
			switch c {
			case '{', '[':
				depth++
				if maxDepth > 0 && depth > maxDepth {
					return ErrNotStrictJSON
				}
			case '}', ']':
				depth--
			case '"':
				inString = true
			}
			i++
			continue
		}
		switch c {
		case '"':
			inString = false
			i++
		case '\\':
			if b[i+1] != 'u' { // json.Valid already guarantees a valid escape
				i += 2
				continue
			}
			cp := hex4(b[i+2:])
			i += 6
			switch {
			case cp >= 0xD800 && cp <= 0xDBFF:
				if i+1 >= len(b) || b[i] != '\\' || b[i+1] != 'u' {
					return ErrNotStrictJSON
				}
				lo := hex4(b[i+2:])
				if lo < 0xDC00 || lo > 0xDFFF {
					return ErrNotStrictJSON
				}
				i += 6
			case cp >= 0xDC00 && cp <= 0xDFFF:
				return ErrNotStrictJSON
			}
		default:
			i++
		}
	}
	return nil
}

// canonicalJSON is the single entry for canonicalizing caller-supplied JSON
// (the JCS, ReceiptID and CostCanon inputs; SSEOutputsHash validates each
// whole message with ValidateJSONText instead). gowebpki/jcs does
// not reject every surrogate misuse (a high escape followed by any other \u
// escape becomes U+FFFD), so the text rule runs first. No depth limit: the
// protocol pins MaxDepth for JWS header and payload text only.
func canonicalJSON(raw json.RawMessage) ([]byte, error) {
	if !json.Valid(raw) || scanText(raw, 0) != nil {
		return nil, ErrNotStrictJSON
	}
	return jcs.Transform(raw)
}

// exceedsMaxDepth reports whether the text nests deeper than MaxDepth. Unlike
// scanText it needs no syntactically valid input, so it can run BEFORE the
// "is this JSON at all" decision: encoding/json stops calling text JSON beyond
// its own depth cap (10000), which would otherwise turn a huge nesting into
// "not JSON, skipped" where the policy says rejected.
func exceedsMaxDepth(b []byte) bool {
	depth := 0
	inString := false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inString {
			if c == '\\' {
				i++
			} else if c == '"' {
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '{', '[':
			depth++
			if depth > MaxDepth {
				return true
			}
		case '}', ']':
			depth--
		}
	}
	return false
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

type tokenFrame struct {
	isObject  bool
	expectKey bool
	keys      map[string]struct{}
}

// walkTokens streams the (already validated) text through json.Decoder with
// UseNumber to find duplicate keys (one key set per open object) and numbers
// that overflow float64. Overflow is detected on the parsed VALUE with
// math.IsInf, not on strconv's error.
func walkTokens(b []byte, p TextPolicy) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var stack []tokenFrame
	valueDone := func() {
		if n := len(stack); n > 0 && stack[n-1].isObject {
			stack[n-1].expectKey = true
		}
	}
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return ErrNotStrictJSON
		}
		if n := len(stack); n > 0 && stack[n-1].isObject && stack[n-1].expectKey {
			if d, ok := tok.(json.Delim); ok && d == '}' {
				stack = stack[:n-1]
				valueDone()
				continue
			}
			key, _ := tok.(string)
			if p.RejectDuplicates {
				if _, seen := stack[n-1].keys[key]; seen {
					return ErrNotStrictJSON
				}
				stack[n-1].keys[key] = struct{}{}
			}
			stack[n-1].expectKey = false
			continue
		}
		switch v := tok.(type) {
		case json.Delim:
			switch v {
			case '{':
				stack = append(stack, tokenFrame{isObject: true, expectKey: true, keys: map[string]struct{}{}})
			case '[':
				stack = append(stack, tokenFrame{})
			default: // ']' (a '}' with expectKey false cannot occur in valid JSON)
				stack = stack[:len(stack)-1]
				valueDone()
			}
		case json.Number:
			if p.RejectNonFinite {
				f, _ := strconv.ParseFloat(string(v), 64)
				if math.IsInf(f, 0) {
					return ErrNotStrictJSON
				}
			}
			valueDone()
		default:
			valueDone()
		}
	}
}
