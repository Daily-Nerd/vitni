package vitni

import (
	"encoding/json"
	"errors"

	"github.com/Daily-Nerd/vitni/go/internal/fields"
	"github.com/gowebpki/jcs"
)

// ErrUnsupportedPart is returned when an A2A part has neither bytes nor uri,
// or an unknown kind.
var ErrUnsupportedPart = errors.New("unsupported_part")

// A2AArtifactHash canonicalizes an A2A artifact into a descriptor and returns
// the JCS bytes of the descriptor plus the pinned outputs_hash.
//
// Each part is mapped, preserving array order, to a canonical descriptor:
//   - text  → {kind:"text", text}
//   - data  → {kind:"data", data}
//   - file inline (bytes present)  → {kind:"file", digest, mimeType|null, name|null}
//   - file by-uri (uri present, no bytes) → {kind:"file", uri, declared_digest|null, mimeType|null, name|null}
//   - otherwise → ErrUnsupportedPart
func A2AArtifactHash(artifact json.RawMessage) (descriptorBytes []byte, outputsHash string, err error) {
	// Member names are exact and case-sensitive (internal/fields); the artifact
	// must be an object with a `parts` array of objects.
	art, err := fields.Object(artifact)
	if err != nil {
		return nil, "", err
	}
	var parts []json.RawMessage
	if err := fields.Required(art, "parts", &parts); err != nil {
		return nil, "", err
	}

	descriptors := make([]json.RawMessage, 0, len(parts))
	for _, partRaw := range parts {
		d, perr := mapPart(partRaw)
		if perr != nil {
			return nil, "", perr
		}
		descriptors = append(descriptors, d)
	}

	descriptor := struct {
		Parts []json.RawMessage `json:"parts"`
	}{Parts: descriptors}

	descriptorJSON, err := json.Marshal(descriptor)
	if err != nil {
		return nil, "", err
	}
	canon, err := jcs.Transform(descriptorJSON)
	if err != nil {
		return nil, "", err
	}
	hashStr, err := Digest(canon)
	if err != nil {
		return nil, "", err
	}
	return canon, hashStr, nil
}

// mapPart maps one A2A part to its canonical descriptor (as JSON bytes).
func mapPart(partRaw json.RawMessage) (json.RawMessage, error) {
	part, err := fields.Object(partRaw)
	if err != nil {
		return nil, err
	}
	var kind string
	if _, err := fields.Field(part, "kind", &kind); err != nil {
		return nil, err
	}

	switch kind {
	case "text":
		// {kind:"text", text}
		d := map[string]json.RawMessage{
			"kind": rawString("text"),
			"text": part["text"],
		}
		return json.Marshal(d)

	case "data":
		// {kind:"data", data}
		d := map[string]json.RawMessage{
			"kind": rawString("data"),
			"data": part["data"],
		}
		return json.Marshal(d)

	case "file":
		var fileRaw json.RawMessage
		if _, err := fields.Field(part, "file", &fileRaw); err != nil {
			return nil, err
		}
		var file map[string]json.RawMessage
		if fileRaw != nil {
			if file, err = fields.Object(fileRaw); err != nil {
				return nil, err
			}
		}
		var bytesB64, uri, mimeType, name *string
		for field, dst := range map[string]**string{"bytes": &bytesB64, "uri": &uri, "mimeType": &mimeType, "name": &name} {
			var v string
			present, err := fields.Field(file, field, &v)
			if err != nil {
				return nil, err
			}
			if present {
				*dst = &v
			}
		}
		if bytesB64 != nil {
			// inline: hash the decoded bytes, do NOT embed.
			raw, err := DecodeStdBase64(*bytesB64)
			if err != nil {
				return nil, err
			}
			digest, err := Digest(raw)
			if err != nil {
				return nil, err
			}
			d := map[string]json.RawMessage{
				"kind":     rawString("file"),
				"digest":   rawString(digest),
				"mimeType": nullableString(mimeType),
				"name":     nullableString(name),
			}
			return json.Marshal(d)
		}
		if uri != nil {
			// by-uri: never dereference. declared_digest passed through (or null).
			declared := json.RawMessage("null")
			if raw, ok := file["declared_digest"]; ok && string(raw) != "null" {
				declared = raw
			}
			d := map[string]json.RawMessage{
				"kind":            rawString("file"),
				"uri":             rawString(*uri),
				"declared_digest": declared,
				"mimeType":        nullableString(mimeType),
				"name":            nullableString(name),
			}
			return json.Marshal(d)
		}
		// neither bytes nor uri
		return nil, ErrUnsupportedPart

	default:
		return nil, ErrUnsupportedPart
	}
}

// rawString marshals a Go string into a JSON string RawMessage.
func rawString(s string) json.RawMessage {
	b, _ := json.Marshal(s)
	return b
}

// nullableString returns a JSON string for a non-nil pointer, else JSON null.
func nullableString(p *string) json.RawMessage {
	if p == nil {
		return json.RawMessage("null")
	}
	return rawString(*p)
}
