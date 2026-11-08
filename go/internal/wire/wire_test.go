package wire_test

import (
	"testing"

	"github.com/Daily-Nerd/vitni/go/internal/wire"
)

func TestDecodeVerifyInput_Keys(t *testing.T) {
	cases := []struct {
		name string
		in   string
		ok   bool
	}{
		{"empty", `{}`, true},
		{"nulls", `{"signed_receipt":null,"keys":null,"policy":null}`, true},
		{"entry", `{"keys":{"p":{"k":{"kty":"OKP","x":"AA"}}}}`, true},
		{"null-entry", `{"keys":{"p":{"k":null}}}`, true},
		{"null-performer", `{"keys":{"p":null}}`, true},
		{"null-member", `{"keys":{"p":{"k":{"kty":null,"x":null}}}}`, true},
		{"unknown-members", `{"extra":5,"keys":{"p":{"k":{"rpId":5,"origins":[]}}}}`, true},
		{"signed-receipt-number", `{"signed_receipt":5}`, false},
		{"keys-array", `{"keys":[]}`, false},
		{"performer-array", `{"keys":{"p":[]}}`, false},
		{"entry-string", `{"keys":{"p":{"k":"x"}}}`, false},
		{"member-number", `{"keys":{"p":{"k":{"x":5}}}}`, false},
		{"unrelated-entry-member-number", `{"keys":{"q":{"k":{"status":5}},"p":{"k":{}}}}`, false},
		{"policy-array", `{"policy":[]}`, false},
		{"policy-member-number", `{"policy":{"expected_method":5}}`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := wire.DecodeVerifyInput([]byte(c.in))
			if (err == nil) != c.ok {
				t.Fatalf("err = %v, want ok=%v", err, c.ok)
			}
		})
	}
}

// A null registry entry is ABSENT: it must not decode into a zero key that a
// later step then judges (that answered alg_not_allowed instead of unknown_key).
func TestDecodeVerifyInput_NullEntryIsAbsent(t *testing.T) {
	in, err := wire.DecodeVerifyInput([]byte(`{"keys":{"p":{"k":null,"j":{"kty":"OKP"}},"q":null}}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, present := in.Keys["p"]["k"]; present {
		t.Error("null entry must be absent, not a zero key")
	}
	if in.Keys["p"]["j"].Kty != "OKP" {
		t.Errorf("a real entry must survive: %+v", in.Keys["p"]["j"])
	}
	if len(in.Keys["q"]) != 0 {
		t.Errorf("null performer must be empty: %v", in.Keys["q"])
	}
}

func TestDecodeVerifyInput_ExactNames(t *testing.T) {
	in, err := wire.DecodeVerifyInput([]byte(`{"Signed_Receipt":"x","KEYS":{"p":{"k":{}}},"POLICY":{"expected_method":"m"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if in.SignedReceipt != "" || len(in.Keys) != 0 || in.Policy.ExpectedMethod != nil {
		t.Errorf("names differing in case must be ignored: %+v", in)
	}
}

func TestDecodeVerifyChainInput(t *testing.T) {
	in, err := wire.DecodeVerifyChainInput([]byte(`{"receipts":["a","b"],"keys":{},"policy":{"expected_binding":"mcp"}}`))
	if err != nil || len(in.Receipts) != 2 || in.Policy.ExpectedBinding == nil || *in.Policy.ExpectedBinding != "mcp" {
		t.Fatalf("got %+v err %v", in, err)
	}
	for _, bad := range []string{`{"receipts":"x"}`, `{"receipts":[5]}`, `{"keys":[]}`, `{"policy":{"expected_binding":5}}`} {
		if _, err := wire.DecodeVerifyChainInput([]byte(bad)); err == nil {
			t.Errorf("%s: want error", bad)
		}
	}
	if in, err := wire.DecodeVerifyChainInput([]byte(`{"receipts":null}`)); err != nil || len(in.Receipts) != 0 {
		t.Errorf("null receipts is an empty chain: %+v %v", in, err)
	}
}
