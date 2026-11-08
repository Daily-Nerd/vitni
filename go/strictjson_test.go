package vitni_test

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	vitni "github.com/Daily-Nerd/vitni/go"
)

func TestDecodeB64URLStrict(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    []byte
		wantErr bool
	}{
		{"empty", "", []byte{}, false},
		{"valid 5 bytes", "aGVsbG8", []byte("hello"), false},
		{"valid url chars", "-_8", []byte{0xfb, 0xff}, false},
		{"padding", "aGVsbG8=", nil, true},
		{"std plus", "a+8", nil, true},
		{"std slash", "a/8", nil, true},
		{"space", "aGVs bG8", nil, true},
		{"carriage return", "aGVs\rbG8", nil, true},
		{"line feed", "aGVs\nbG8", nil, true},
		{"trailing line feed", "aGVsbG8\n", nil, true},
		{"length 1 mod 4", "aGVsb", nil, true},
		{"non-zero trailing bits", "aGVsbG9", nil, true},
		{"non-ascii", "aGVsbé", nil, true},
		{"nul byte", "aGVs\x00bG8", nil, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := vitni.DecodeB64URLStrict(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("DecodeB64URLStrict(%q) err = %v, wantErr %v", tc.in, err, tc.wantErr)
			}
			if !tc.wantErr && !bytes.Equal(got, tc.want) {
				t.Fatalf("DecodeB64URLStrict(%q) = %x, want %x", tc.in, got, tc.want)
			}
		})
	}
}

// TestNoSecondB64URLDecoder guards the single-owner invariant: every base64url
// DECODE goes through DecodeB64URLStrict. Encoding is fine anywhere; a decode
// with the stdlib outside strictjson.go is a second, lenient owner of the format.
func TestNoSecondB64URLDecoder(t *testing.T) {
	re := regexp.MustCompile(`URLEncoding(\.Strict\(\))?\.Decode(String)?\(|base64\.NewDecoder\(`)
	var offenders []string
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if filepath.Base(path) == "strictjson.go" {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if re.Match(src) {
			offenders = append(offenders, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Fatalf("base64url decoded outside strictjson.go: %v", offenders)
	}
}

func TestValidateJSONText(t *testing.T) {
	deep := func(n int) string { return strings.Repeat("[", n) + strings.Repeat("]", n) }
	none := vitni.TextPolicy{}
	dup := vitni.TextPolicy{RejectDuplicates: true}
	nf := vitni.TextPolicy{RejectNonFinite: true}
	both := vitni.TextPolicy{RejectDuplicates: true, RejectNonFinite: true}

	tests := []struct {
		name    string
		in      string
		policy  vitni.TextPolicy
		wantErr bool
	}{
		{"object", `{"a":1}`, none, false},
		{"trailing whitespace", "{\"a\":1} \n\t", none, false},
		{"array is valid text", `[1,2]`, none, false},
		{"empty", ``, none, true},
		{"bom", "\xef\xbb\xbf{\"a\":1}", none, true},
		{"invalid utf8 in string", "{\"a\":\"\xff\"}", none, true},
		{"overlong utf8", "{\"a\":\"\xc0\x80\"}", none, true},
		{"utf8 encoded surrogate", "{\"a\":\"\xed\xa0\x80\"}", none, true},
		{"lone high escape", `{"a":"\ud800"}`, none, true},
		{"lone low escape", `{"a":"\udc00"}`, none, true},
		{"lone surrogate in key", `{"\ud800":1}`, none, true},
		{"high then non-low escape", `{"a":"\ud800A"}`, none, true},
		{"low then high (reversed pair)", `{"a":"\ude00\ud83d"}`, none, true},
		{"high at end of string", `{"a":"x\ud800"}`, none, true},
		{"lone high escape uppercase", `{"a":"\uD800"}`, none, true},
		{"lone low escape uppercase", `{"a":"\uDC00"}`, none, true},
		{"high then high escape", `{"a":"\ud800\ud800"}`, none, true},
		{"high then high escape uppercase", `{"a":"\uD800\uD800"}`, none, true},
		{"high then non-surrogate escape", `{"a":"\ud800\u0041"}`, none, true},
		{"valid pair escape lowercase", `{"a":"\ud83d\ude00"}`, none, false},
		{"valid pair escape uppercase", `{"a":"\uD83D\uDE00"}`, none, false},
		{"valid pair escape mixed case", `{"a":"\uD83d\uDe00"}`, none, false},
		{"valid pair escape", `{"a":"😀"}`, none, false},
		{"escaped backslash is not an escape", `{"a":"\\ud800"}`, none, false},
		{"raw non-bmp", "{\"a\":\"\U0001F600\"}", none, false},
		{"depth 128 ok", deep(128), none, false},
		{"depth 129 rejected", deep(129), none, true},
		{"depth 128 objects ok", strings.Repeat(`{"a":`, 128) + `1` + strings.Repeat(`}`, 128), none, false},
		{"depth 129 objects rejected", strings.Repeat(`{"a":`, 129) + `1` + strings.Repeat(`}`, 129), none, true},
		{"brackets inside string do not count", `{"a":"` + strings.Repeat("[", 500) + `"}`, none, false},
		{"duplicate allowed when off", `{"a":1,"a":2}`, none, false},
		{"duplicate rejected when on", `{"a":1,"a":2}`, dup, true},
		{"nested duplicate rejected when on", `{"x":{"a":1,"a":2}}`, dup, true},
		{"duplicate via escape rejected when on", `{"a":1,"a":2}`, dup, true},
		{"same key in sibling objects is fine", `{"x":{"a":1},"y":{"a":2}}`, dup, false},
		{"same key in array elements is fine", `[{"a":1},{"a":2}]`, dup, false},
		{"duplicate inside array element rejected", `[{"a":1,"a":2}]`, dup, true},
		{"non-finite accepted when off", `{"a":1e400}`, none, false},
		{"non-finite rejected when on", `{"a":1e400}`, nf, true},
		{"negative non-finite rejected when on", `{"a":-1e400}`, nf, true},
		{"non-finite nested rejected when on", `{"a":[{"b":1e999}]}`, both, true},
		{"underflow is finite", `{"a":1e-400}`, nf, false},
		{"large finite", `{"a":1.7976931348623157e308}`, nf, false},
		{"trailing garbage", `{"a":1} x`, none, true},
		{"two values", `{"a":1}{"b":2}`, none, true},
		{"nul suffix", "{\"a\":1}\x00", none, true},
		{"not json", `{not json`, none, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := vitni.ValidateJSONText([]byte(tc.in), tc.policy)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateJSONText(%q) err = %v, wantErr %v", tc.in, err, tc.wantErr)
			}
		})
	}
}

// TestJWSTextOnlyThroughDecodeObject guards the single-owner invariant for JWS
// header and payload bytes: verify.go and chain.go never json.Unmarshal those
// bytes directly (that is lenient: BOM-tolerant callers, null-into-map, no
// surrogate or depth rules). decodeObject in strictjson.go is the one entry.
func TestJWSTextOnlyThroughDecodeObject(t *testing.T) {
	re := regexp.MustCompile(`json\.Unmarshal\((headerBytes|payloadBytes|b)\b`)
	for _, f := range []string{"verify.go", "chain.go"} {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if re.Match(src) {
			t.Errorf("%s unmarshals JWS header/payload bytes directly; use decodeObject", f)
		}
	}
}
