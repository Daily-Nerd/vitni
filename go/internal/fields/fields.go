// Package fields is the single owner of member extraction from untrusted JSON
// objects: exact, case-sensitive member names and explicit JSON types.
//
// encoding/json matches an object member onto a struct tag case-insensitively
// ("Signed_Receipt" fills `json:"signed_receipt"`), which silently diverges
// from every implementation that matches names exactly. Everything that reads
// a member of untrusted input goes through Object, Field and Required instead
// of unmarshalling into a tagged struct. The text has already passed
// vitni.ValidateJSONText, so a failure here is a SHAPE problem (wrong type, absent
// required member), reported as one error the caller maps to invalid_input.
package fields

import (
	"bytes"
	"encoding/json"
	"errors"
)

// ErrShape reports an input whose JSON shape is not the one required.
var ErrShape = errors.New("fields: input has the wrong shape")

// Object decodes raw as a JSON object. null, arrays and scalars are not objects.
func Object(raw []byte) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, ErrShape
	}
	return m, nil
}

// Field decodes the member called exactly `name` into dst. An absent member and
// a JSON null are both "not present": present is false and dst is untouched.
// A present member of the wrong JSON type is ErrShape.
func Field(m map[string]json.RawMessage, name string, dst any) (present bool, err error) {
	raw, ok := m[name]
	if !ok {
		return false, nil
	}
	return Value(raw, dst)
}

// Value decodes one raw JSON value into dst with the same rules as Field: a
// JSON null is "not present" (dst untouched), the wrong type is ErrShape.
func Value(raw json.RawMessage, dst any) (present bool, err error) {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return false, nil
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return true, ErrShape
	}
	return true, nil
}

// Required is Field for a member that must be present: absent, null and the
// wrong type are all ErrShape.
func Required(m map[string]json.RawMessage, name string, dst any) error {
	present, err := Field(m, name, dst)
	if err != nil {
		return err
	}
	if !present {
		return ErrShape
	}
	return nil
}
