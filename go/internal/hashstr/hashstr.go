// Package hashstr is the single owner of the pinned hash-string encoding
// (DESIGN section 4.2): "u" + base64url-nopad(0x12 || 0x20 || sha2-256 digest).
//
// It lives in an internal package so that package vitni and the CLI share one
// infallible helper without widening the public API of package vitni.
package hashstr

import (
	"crypto/sha256"
	"encoding/base64"
)

// Encode renders a raw digest as a hash-string: varint(0x12), the multihash
// code for sha2-256, then varint(0x20), the length 32, then the digest bytes.
func Encode(digest []byte) string {
	mh := make([]byte, 2+len(digest))
	mh[0] = 0x12
	mh[1] = 0x20
	copy(mh[2:], digest)
	return "u" + base64.RawURLEncoding.EncodeToString(mh)
}

// Sum hashes raw with sha2-256 and returns its hash-string. It cannot fail.
func Sum(raw []byte) string {
	h := sha256.Sum256(raw)
	return Encode(h[:])
}
