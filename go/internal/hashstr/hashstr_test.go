package hashstr

import (
	"crypto/sha256"
	"testing"
)

func TestSum(t *testing.T) {
	cases := map[string]string{
		"":      "uEiDjsMRCmPwcFJr79MiZb7kkJ65B5GSbk0yklZkbeFK4VQ",
		"hello": "uEiAs8k26X7CjDiboOyrFueKeGxYeXB-nQl5zBDNik4uYJA",
	}
	for in, want := range cases {
		if got := Sum([]byte(in)); got != want {
			t.Errorf("Sum(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEncodeIsSumOverTheDigest(t *testing.T) {
	h := sha256.Sum256([]byte("hello"))
	if got, want := Encode(h[:]), Sum([]byte("hello")); got != want {
		t.Errorf("Encode(sha256(hello)) = %q, want %q", got, want)
	}
}
