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
	out := Fill(tpl, map[string][]byte{
		"sesh://password/db/app":      []byte("pw"),
		"sesh://password/db/app#host": []byte("db.internal"),
	})
	want := "db:\n  password: pw\n  host: db.internal\n  again: pw\n  other: {{ not a ref }}\n"
	if string(out) != want {
		t.Errorf("Fill = %q, want %q", out, want)
	}
	if _, err := TemplateRefs("a\nb: {{ sesh://openai }}", "config.tpl"); err == nil || !strings.Contains(err.Error(), "config.tpl line 2: sesh://openai") {
		t.Errorf("bad ref: %v", err)
	}
}
