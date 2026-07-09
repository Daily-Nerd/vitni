package vitni

import (
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/gowebpki/jcs"
)

// ErrUnsupportedPart is returned when an A2A part has neither bytes nor uri,
// or an unknown kind.
var ErrUnsupportedPart = errors.New("unsupported_part")

// a2aArtifact is the input artifact shape.
type a2aArtifact struct {
	Parts []json.RawMessage `json:"parts"`
}

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
	var art a2aArtifact
	if err := json.Unmarshal(artifact, &art); err != nil {
		return nil, "", err
	}

	descriptors := make([]json.RawMessage, 0, len(art.Parts))
	for _, partRaw := range art.Parts {
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

// a2aFile is the file sub-object of a file part.
type a2aFile struct {
	Bytes          *string         `json:"bytes"`
	URI            *string         `json:"uri"`
	MimeType       *string         `json:"mimeType"`
	Name           *string         `json:"name"`
	DeclaredDigest json.RawMessage `json:"declared_digest"`
}

// mapPart maps one A2A part to its canonical descriptor (as JSON bytes).
func mapPart(partRaw json.RawMessage) (json.RawMessage, error) {
	var part struct {
		Kind string          `json:"kind"`
		Text json.RawMessage `json:"text"`
		Data json.RawMessage `json:"data"`
		File json.RawMessage `json:"file"`
	}
	if err := json.Unmarshal(partRaw, &part); err != nil {
		return nil, err
	}

	switch part.Kind {
	case "text":
		// {kind:"text", text}
		d := map[string]json.RawMessage{
			"kind": rawString("text"),
			"text": part.Text,
		}
		return json.Marshal(d)

	case "data":
		// {kind:"data", data}
		d := map[string]json.RawMessage{
			"kind": rawString("data"),
			"data": part.Data,
		}
		return json.Marshal(d)

	case "file":
		var f a2aFile
		if len(part.File) > 0 {
			if err := json.Unmarshal(part.File, &f); err != nil {
				return nil, err
			}
		}
		if f.Bytes != nil {
			// inline: hash the decoded bytes, do NOT embed.
			raw, err := base64.StdEncoding.DecodeString(*f.Bytes)
			if err != nil {
				raw, err = base64.RawStdEncoding.DecodeString(*f.Bytes)
				if err != nil {
					return nil, err
				}
			}
			digest, err := Digest(raw)
			if err != nil {
				return nil, err
			}
			d := map[string]json.RawMessage{
				"kind":     rawString("file"),
				"digest":   rawString(digest),
				"mimeType": nullableString(f.MimeType),
				"name":     nullableString(f.Name),
			}
			return json.Marshal(d)
		}
		if f.URI != nil {
			// by-uri: never dereference. declared_digest passed through (or null).
			declared := json.RawMessage("null")
			if len(f.DeclaredDigest) > 0 && string(f.DeclaredDigest) != "null" {
				declared = f.DeclaredDigest
			}
			d := map[string]json.RawMessage{
				"kind":            rawString("file"),
				"uri":             rawString(*f.URI),
				"declared_digest": declared,
				"mimeType":        nullableString(f.MimeType),
				"name":            nullableString(f.Name),
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
