package sitematch

import "testing"

func TestMatches(t *testing.T) {
	for _, tc := range []struct {
		kept, scheme, host string
		want               bool
	}{
		{"https://github.com/login", "https", "github.com", true},
		{"github.com", "https", "github.com", true},                   // no scheme: https
		{"github.com", "http", "github.com", false},                   // ... so never http
		{"https://GitHub.com", "HTTPS", "github.COM", true},           // case aside
		{"https://github.com:443/x", "https", "github.com", true},     // https's own port
		{"https://github.com", "https", "github.com:443", true},       // either side
		{"http://intranet:80", "http", "intranet", true},              // http's own port
		{"https://github.com:8443", "https", "github.com", false},     // another port
		{"https://github.com:8443", "https", "github.com:8443", true}, // the same one
		{"https://github.com", "http", "github.com", false},           // no downgrade
		{"https://github.com", "https", "gist.github.com", false},     // not a parent's
		{"https://gist.github.com", "https", "github.com", false},     // nor a child's
		{"https://github.com.evil.example", "https", "github.com", false},
		{"", "https", "github.com", false},
		{"https://github.com", "", "github.com", false},
		{"https://github.com", "https", "", false},
		{"://bad", "https", "github.com", false},
	} {
		if got := Matches(tc.kept, tc.scheme, tc.host); got != tc.want {
			t.Errorf("Matches(%q, %q, %q) = %v, want %v", tc.kept, tc.scheme, tc.host, got, tc.want)
		}
	}
}

func TestOf(t *testing.T) {
	for page, want := range map[string]string{
		"https://github.com/login?x=1": "https github.com",
		"HTTP://Intranet:8080/":        "http Intranet:8080",
		"chrome://settings":            "",
		"file:///etc/passwd":           "",
		"about:blank":                  "",
		"https:///nohost":              "",
		"not a url":                    "",
	} {
		scheme, host, ok := Of(page)
		got := ""
		if ok {
			got = scheme + " " + host
		}
		if got != want {
			t.Errorf("Of(%q) = %q, want %q", page, got, want)
		}
	}
}
