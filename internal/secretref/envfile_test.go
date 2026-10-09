package secretref

import (
	"strings"
	"testing"
)

func TestParseEnvFile(t *testing.T) {
	in := `# a comment
OPENAI_API_KEY=sesh://api_key/openai

export DB_PASSWORD="sesh://password/db/app"
DB_HOST='db.internal'
EMPTY=
GREETING="hello world"   
URL=https://x.example/?a=b#frag
`
	got, err := ParseEnvFile(strings.NewReader(in), ".env")
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, v := range got {
		s := v.Name + "="
		if v.Ref != nil {
			s += "ref:" + v.Ref.String()
		} else {
			s += v.Value
		}
		lines = append(lines, s)
	}
	want := "OPENAI_API_KEY=ref:sesh://api_key/openai|DB_PASSWORD=ref:sesh://password/db/app|DB_HOST=db.internal|EMPTY=|GREETING=hello world|URL=https://x.example/?a=b#frag"
	if strings.Join(lines, "|") != want {
		t.Errorf("got  %s\nwant %s", strings.Join(lines, "|"), want)
	}

	for bad, wantSub := range map[string]string{
		"NOVALUE":                       ".env line 1: want NAME=value",
		"1BAD=x":                        `.env line 1: "1BAD" isn't a variable name`,
		"A=x\nA=y":                      ".env line 2: A is set twice",
		`A="unclosed`:                   ".env line 1: the quote isn't closed",
		"A=sesh://password":             ".env line 1: sesh://password: entry ID",
		"A=x\nB=sesh://api_key/o#bad x": ".env line 2: sesh://api_key/o#bad x",
	} {
		if _, err := ParseEnvFile(strings.NewReader(bad), ".env"); err == nil || !strings.Contains(err.Error(), wantSub) {
			t.Errorf("%q: %v, want an error containing %q", bad, err, wantSub)
		}
	}
}

func TestParseEnvFlag(t *testing.T) {
	v, err := ParseEnvFlag("KEY=sesh://api_key/openai")
	if err != nil || v.Name != "KEY" || v.Ref == nil || v.Ref.String() != "sesh://api_key/openai" {
		t.Errorf("ParseEnvFlag = %+v, %v", v, err)
	}
	if v, err := ParseEnvFlag("PLAIN=value"); err != nil || v.Ref != nil || v.Value != "value" {
		t.Errorf("plain: %+v, %v", v, err)
	}
	if _, err := ParseEnvFlag("KEY"); err == nil || !strings.Contains(err.Error(), "--env wants NAME=value") {
		t.Errorf("no =: %v", err)
	}
}

// Comments after a value, a byte-order mark, a tab after export, and CRLF
// line ends are read as dotenv files write them.
func TestParseEnvFile_Forms(t *testing.T) {
	in := "\ufeffA=plain # a note\r\nexport\tB=sesh://api_key/openai  # the key\r\nC=\"quoted # kept\"\r\nD=no#comment\r\n"
	got, err := ParseEnvFile(strings.NewReader(in), ".env")
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, v := range got {
		if v.Ref != nil {
			lines = append(lines, v.Name+"=ref:"+v.Ref.String())
		} else {
			lines = append(lines, v.Name+"="+v.Value)
		}
	}
	if want := "A=plain|B=ref:sesh://api_key/openai|C=quoted # kept|D=no#comment"; strings.Join(lines, "|") != want {
		t.Errorf("got  %s\nwant %s", strings.Join(lines, "|"), want)
	}
}
