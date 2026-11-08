package fields_test

import (
	"encoding/json"
	"testing"

	"github.com/Daily-Nerd/vitni/go/internal/fields"
)

func TestObject(t *testing.T) {
	cases := []struct {
		name string
		in   string
		ok   bool
	}{
		{"object", `{"a":1}`, true},
		{"empty-object", `{}`, true},
		{"null", `null`, false},
		{"array", `[]`, false},
		{"string", `"x"`, false},
		{"number", `5`, false},
		{"empty", ``, false},
		{"garbage", `{`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, err := fields.Object([]byte(c.in))
			if (err == nil) != c.ok {
				t.Fatalf("err = %v, want ok=%v", err, c.ok)
			}
			if c.ok && m == nil {
				t.Error("nil map for an object")
			}
		})
	}
}

// Member names are exact and case-sensitive: encoding/json would have matched
// every variant below onto the struct tag.
func TestFieldExactName(t *testing.T) {
	m, err := fields.Object([]byte(`{"Value":"x","VALUE":"y","value ":"z"}`))
	if err != nil {
		t.Fatal(err)
	}
	var s string
	present, err := fields.Field(m, "value", &s)
	if err != nil || present {
		t.Errorf("value: present=%v err=%v, want absent", present, err)
	}
	present, err = fields.Field(m, "Value", &s)
	if err != nil || !present || s != "x" {
		t.Errorf("Value: present=%v err=%v s=%q", present, err, s)
	}
}

func TestField(t *testing.T) {
	m, _ := fields.Object([]byte(`{"s":"x","n":5,"z":null,"o":{"a":1},"a":["p"]}`))
	var s string
	if p, err := fields.Field(m, "s", &s); !p || err != nil || s != "x" {
		t.Errorf("string: %v %v %q", p, err, s)
	}
	if _, err := fields.Field(m, "n", &s); err == nil {
		t.Error("number into string must fail")
	}
	if _, err := fields.Field(m, "o", &s); err == nil {
		t.Error("object into string must fail")
	}
	s = "keep"
	if p, err := fields.Field(m, "z", &s); p || err != nil || s != "keep" {
		t.Errorf("null is absent and leaves dst alone: %v %v %q", p, err, s)
	}
	if p, err := fields.Field(m, "missing", &s); p || err != nil {
		t.Errorf("missing: %v %v", p, err)
	}
	var arr []string
	if p, err := fields.Field(m, "a", &arr); !p || err != nil || len(arr) != 1 {
		t.Errorf("array: %v %v %v", p, err, arr)
	}
	var raw json.RawMessage
	if p, err := fields.Field(m, "o", &raw); !p || err != nil || string(raw) != `{"a":1}` {
		t.Errorf("raw: %v %v %s", p, err, raw)
	}
}

func TestRequired(t *testing.T) {
	m, _ := fields.Object([]byte(`{"s":"x","z":null,"n":5}`))
	var s string
	if err := fields.Required(m, "s", &s); err != nil || s != "x" {
		t.Errorf("present: %v %q", err, s)
	}
	for _, name := range []string{"missing", "z", "n"} {
		if err := fields.Required(m, name, &s); err == nil {
			t.Errorf("%s: absent, null and wrong type must fail", name)
		}
	}
}

func TestValue(t *testing.T) {
	var s string
	if p, err := fields.Value(json.RawMessage(`"x"`), &s); !p || err != nil || s != "x" {
		t.Errorf("string: %v %v %q", p, err, s)
	}
	if p, err := fields.Value(json.RawMessage(` null `), &s); p || err != nil {
		t.Errorf("null: %v %v", p, err)
	}
	if _, err := fields.Value(json.RawMessage(`5`), &s); err == nil {
		t.Error("number into string must fail")
	}
}
