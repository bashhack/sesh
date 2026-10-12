package browser

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/bashhack/sesh/internal/importer"
	"github.com/bashhack/sesh/internal/vault"
)

// Entries is the password entries an export's logins become, in order.
// Each is named for its site, without a leading "www." (port kept), with
// the address as its URL; an app's login (Chrome's android://…) is named
// as Chrome names it. Two of one name and username get " (2)", and a
// login with no password is skipped.
func Entries(exp *Export) []*importer.Entry {
	names := importer.NewNames()
	var out []*importer.Entry
	for i := range exp.Logins {
		l := &exp.Logins[i]
		site := siteName(l)
		e := &importer.Entry{Name: site, Created: l.Created, Updated: l.Updated}
		service := importer.FitName(site)
		user := importer.FitName(l.Username)
		switch {
		case service == "":
			e.Skip = "it has no site"
		case l.Password == "":
			e.Skip = "it has no password"
		}
		if e.Skip != "" {
			out = append(out, e)
			continue
		}
		if service != site {
			e.Changes = append(e.Changes, fmt.Sprintf("named %q in sesh", service))
		}
		if user != l.Username {
			e.Changes = append(e.Changes, fmt.Sprintf("username %q in sesh", user))
		}
		var fs importer.FieldSet
		fs.Add("http-realm", l.Realm, false)
		e.Key = vault.Key{Kind: vault.KindPassword, Service: service, Username: user}
		e.Secret = []byte(l.Password)
		e.Details = vault.Details{URL: l.URL, Fields: fs.Fields}
		if l.Note != "" {
			e.Details.Notes = []byte(l.Note)
		}
		e.Changes = append(e.Changes, fs.Changes...)
		importer.Place([]*importer.Entry{e}, names)
		out = append(out, e)
	}
	return out
}

// siteName is what a login is named for: its web address's host, without
// a leading "www.", or for anything else Chrome's name for it, or the
// address itself.
func siteName(l *Login) string {
	if u, err := url.Parse(l.URL); err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" {
		return strings.TrimPrefix(u.Host, "www.")
	}
	if l.Name != "" {
		return l.Name
	}
	return l.URL
}
