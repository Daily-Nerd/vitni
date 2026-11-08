package vitni

import (
	"encoding/base64"
	"errors"
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
