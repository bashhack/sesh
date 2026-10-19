// Package sitematch says whether a URL kept with an entry is a site's,
// for the programs that fill a site's password from sesh: git's
// credential helper and the browser's.
//
// A kept URL is the site's when it has the same scheme, the same host,
// and the same port, a scheme's own port (443 for https, 80 for http)
// left out of both; a kept URL with no scheme counts as https. The host
// must be the same, not a parent: one kept for github.com isn't
// gist.github.com's, and an https URL never matches an http page.
package sitematch

import (
	"net/url"
	"strings"
)

// Matches says whether kept, a URL kept with an entry, is the site at
// scheme and host (with its port, when it has one), case aside.
func Matches(kept, scheme, host string) bool {
	if kept == "" || scheme == "" || host == "" {
		return false
	}
	raw := kept
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(u.Scheme, scheme) {
		return false
	}
	return strings.EqualFold(withoutOwnPort(u.Host, u.Scheme), withoutOwnPort(host, scheme))
}

// Of is the scheme and host (with its port) of a page's URL; ok is false
// for one that isn't an http or https page with a host.
func Of(page string) (scheme, host string, ok bool) {
	u, err := url.Parse(page)
	if err != nil || u.Host == "" {
		return "", "", false
	}
	switch scheme = strings.ToLower(u.Scheme); scheme {
	case "https", "http":
		return scheme, u.Host, true
	}
	return "", "", false
}

// withoutOwnPort is host without :443 for https, or :80 for http.
func withoutOwnPort(host, scheme string) string {
	switch strings.ToLower(scheme) {
	case "https":
		return strings.TrimSuffix(host, ":443")
	case "http":
		return strings.TrimSuffix(host, ":80")
	}
	return host
}
