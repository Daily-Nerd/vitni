// Package wire decodes the stdin documents of the conformance CLI that carry a
// registry (verify, verify-chain) into the library's input types. It is the
// single decoder for that format: the CLI and the library's vector tests both
// go through it, so no second, lenient decoder exists.
package wire

import (
	"encoding/json"

	vitni "github.com/Daily-Nerd/vitni/go"
	"github.com/Daily-Nerd/vitni/go/internal/fields"
)

// Member names are exact and case-sensitive and every member has an explicit
// JSON type (internal/fields); a wrong type ANYWHERE in the typed part of the
// input is an error the CLI reports as invalid_input, a command error and never
// a verdict. Unknown members are ignored, so the input can grow (a registry
// entry may carry rpId or origins).

// RequiredObject returns the raw JSON of member `name`, which must be present,
// non-null and a JSON object.
func RequiredObject(m map[string]json.RawMessage, name string) (json.RawMessage, error) {
	var raw json.RawMessage
	if err := fields.Required(m, name, &raw); err != nil {
		return nil, err
	}
	if _, err := fields.Object(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// DecodeVerifyInput decodes the verify command input.
func DecodeVerifyInput(stdin []byte) (vitni.VerifyInput, error) {
	var in vitni.VerifyInput
	m, err := fields.Object(stdin)
	if err != nil {
		return in, err
	}
	// signed_receipt: a string; absent or null stays "" and Verify answers
	// malformed (the one required member whose absence is a verdict).
	if _, err := fields.Field(m, "signed_receipt", &in.SignedReceipt); err != nil {
		return in, err
	}
	if in.Keys, err = decodeKeys(m); err != nil {
		return in, err
	}
	in.Policy, err = decodePolicy(m)
	return in, err
}

// DecodeVerifyChainInput decodes the verify-chain command input.
func DecodeVerifyChainInput(stdin []byte) (vitni.VerifyChainInput, error) {
	var in vitni.VerifyChainInput
	m, err := fields.Object(stdin)
	if err != nil {
		return in, err
	}
	// receipts: an array of strings; absent or null is an empty chain.
	if _, err := fields.Field(m, "receipts", &in.Receipts); err != nil {
		return in, err
	}
	if in.Keys, err = decodeKeys(m); err != nil {
		return in, err
	}
	in.Policy, err = decodePolicy(m)
	return in, err
}

// decodeKeys types the WHOLE `keys` tree (performer -> kid -> entry), not only
// the entry a receipt resolves to: a bad type in an unrelated entry is
// invalid_input too, so the accept set does not depend on which entry is hit.
func decodeKeys(m map[string]json.RawMessage) (map[string]map[string]vitni.RegistryKey, error) {
	var performers map[string]json.RawMessage
	if _, err := fields.Field(m, "keys", &performers); err != nil {
		return nil, err
	}
	keys := make(map[string]map[string]vitni.RegistryKey, len(performers))
	for performer, raw := range performers {
		var entries map[string]json.RawMessage
		if _, err := fields.Value(raw, &entries); err != nil {
			return nil, err
		}
		decoded := make(map[string]vitni.RegistryKey, len(entries))
		for kid, entry := range entries {
			key, err := decodeRegistryKey(entry)
			if err != nil {
				return nil, err
			}
			decoded[kid] = key
		}
		keys[performer] = decoded
	}
	return keys, nil
}

// decodeRegistryKey decodes one registry entry: kty, crv, x, y, alg and status
// are each a string, null or absent (null and absent are ""). A JSON null entry
// is the zero key.
func decodeRegistryKey(raw json.RawMessage) (vitni.RegistryKey, error) {
	var key vitni.RegistryKey
	var obj map[string]json.RawMessage
	if _, err := fields.Value(raw, &obj); err != nil {
		return key, err
	}
	for name, dst := range map[string]*string{
		"kty": &key.Kty, "crv": &key.Crv, "x": &key.X, "y": &key.Y, "alg": &key.Alg, "status": &key.Status,
	} {
		if _, err := fields.Field(obj, name, dst); err != nil {
			return key, err
		}
	}
	return key, nil
}

// decodePolicy decodes `policy`: an object or null/absent whose
// expected_binding and expected_method are each a string, null or absent.
func decodePolicy(m map[string]json.RawMessage) (vitni.VerifyPolicy, error) {
	var policy vitni.VerifyPolicy
	var obj map[string]json.RawMessage
	if _, err := fields.Field(m, "policy", &obj); err != nil {
		return policy, err
	}
	for name, dst := range map[string]**string{
		"expected_binding": &policy.ExpectedBinding, "expected_method": &policy.ExpectedMethod,
	} {
		var s string
		present, err := fields.Field(obj, name, &s)
		if err != nil {
			return policy, err
		}
		if present {
			*dst = &s
		}
	}
	return policy, nil
}
