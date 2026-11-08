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
