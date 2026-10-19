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
		{"  github.com  ", "https", "github.com", true},                               // spaces around it
		{"github.com/login?return_to=https://x.example", "https", "github.com", true}, // :// in its query
		{"github.com/login", "https", "github.com", true},                             // a path, no scheme
		{"github.com:8443", "https", "github.com:8443", true},                         // a port, no scheme
		{"github.com:8443", "https", "github.com", false},
		{"https://github.com.", "https", "github.com", false}, // a trailing dot: another origin
		{"https://[::1]:8443", "https", "[::1]:8443", true},
		{"https://[::1]", "https", "[::1]:8443", false},
	} {
		if got := Matches(tc.kept, tc.scheme, tc.host); got != tc.want {
			t.Errorf("Matches(%q, %q, %q) = %v, want %v", tc.kept, tc.scheme, tc.host, got, tc.want)
		}
	}
}

func TestOf(t *testing.T) {
	for page, want := range map[string]string{
		"https://github.com/login?x=1":       "https github.com",
		"HTTP://Intranet:8080/":              "http Intranet:8080",
		"chrome://settings":                  "",
		"file:///etc/passwd":                 "",
		"about:blank":                        "",
		"https:///nohost":                    "",
		"not a url":                          "",
		"https://github.com@evil.example/":   "https evil.example", // the userinfo isn't the host
		"https://[::1]:8443/x":               "https [::1]:8443",
		"https://github.com\\@evil.example/": "",
		"https://github.com%2e/":             "",
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
