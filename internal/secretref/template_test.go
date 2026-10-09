package secretref

import (
	"strings"
	"testing"
)

func TestTemplate(t *testing.T) {
	tpl := "db:\n  password: {{ sesh://password/db/app }}\n  host: {{sesh://password/db/app#host}}\n  again: {{  sesh://password/db/app }}\n  other: {{ not a ref }}\n"
	refs, err := TemplateRefs(tpl, "config.tpl")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, r := range refs {
		names = append(names, r.String())
	}
	if strings.Join(names, " ") != "sesh://password/db/app sesh://password/db/app#host" {
		t.Errorf("refs = %v, want each once", names)
	}
	out, err := Fill(tpl, map[string][]byte{
		"sesh://password/db/app":      []byte("pw"),
		"sesh://password/db/app#host": []byte("db.internal"),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "db:\n  password: pw\n  host: db.internal\n  again: pw\n  other: {{ not a ref }}\n"
	if string(out) != want {
		t.Errorf("Fill = %q, want %q", out, want)
	}
	if _, err := TemplateRefs("a\nb: {{ sesh://openai }}", "config.tpl"); err == nil || !strings.Contains(err.Error(), "config.tpl line 2: sesh://openai") {
		t.Errorf("bad ref: %v", err)
	}
}

// A reference is filled however it's written, and one without a value is
// an error, not left in place.
func TestFill_Forms(t *testing.T) {
	out, err := Fill("{{ sesh://api_key/openai/ }} {{sesh://api_key/openai}}", map[string][]byte{"sesh://api_key/openai": []byte("v")})
	if err != nil || string(out) != "v v" {
		t.Errorf("Fill = %q, %v", out, err)
	}
	if _, err := Fill("{{ sesh://api_key/other }}", map[string][]byte{}); err == nil || !strings.Contains(err.Error(), "sesh://api_key/other has no value") {
		t.Errorf("missing value: %v", err)
	}
}
