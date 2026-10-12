package browser

import (
	"fmt"
	"net/url"
	"slices"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/text/unicode/bidi"

	"github.com/bashhack/sesh/internal/importer"
	"github.com/bashhack/sesh/internal/vault"
)

// firefoxAccount is the address of Firefox's own sign-in to the user's
// Mozilla account (FxAccountsCommon.sys.mjs FXA_PWDMGR_HOST), which its
// export includes though its password manager hides it
// (LoginHelper.sys.mjs isUserFacingLogin).
const firefoxAccount = "chrome://FirefoxAccounts"

// Entries is the password entries an export's logins become, in order.
// Each is named for its site (see siteName), with the address as its URL.
// Two of one name and username get " (2)", unless the password is the
// same too: Chrome writes a row for each address of one login, and the
// repeats are skipped. A login with no password is skipped, as is
// Firefox's sign-in to the Mozilla account.
func Entries(exp *Export) []*importer.Entry {
	names := importer.NewNames()
	type login struct{ site, user, password string }
	seen := map[login]bool{}
	var out []*importer.Entry
	for i := range exp.Logins {
		l := &exp.Logins[i]
		site := siteName(l)
		e := &importer.Entry{Name: site, Created: l.Created, Updated: l.Updated}
		service := importer.FitName(site)
		user := importer.FitName(l.Username)
		switch {
		case l.URL == firefoxAccount:
			e.Skip = "Firefox's own sign-in to your Mozilla account"
		case service == "":
			e.Skip = "it has no site"
		case l.Password == "":
			e.Skip = "it has no password"
		case seen[login{site, l.Username, l.Password}]:
			e.Skip = "the same login as an earlier one, for another address on the site"
		}
		if e.Skip != "" {
			out = append(out, e)
			continue
		}
		seen[login{site, l.Username, l.Password}] = true
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

// siteName is what a login is named for:
//   - an Android app's (Chrome's android://hash@package/) as Chrome names
//     it, or, where it gave no name, as Chrome would: the package reversed
//     (affiliation_utils.cc GetAndroidPackageDisplayName);
//   - an address with a host, the host without a leading "www.", in
//     Unicode as Chrome shows it (elide_url.cc HostForDisplay: punycode
//     kept when the Unicode has a right-to-left letter);
//   - anything else, Chrome's name for it, or the address itself.
func siteName(l *Login) string {
	u, err := url.Parse(l.URL)
	if err != nil {
		return l.URL
	}
	if u.Scheme == "android" {
		if l.Name != "" {
			return l.Name
		}
		parts := strings.Split(u.Hostname(), ".")
		slices.Reverse(parts)
		return strings.Join(parts, ".")
	}
	if u.Host == "" {
		if l.Name != "" {
			return l.Name
		}
		return l.URL
	}
	host := strings.TrimPrefix(u.Hostname(), "www.")
	if strings.Contains(host, ":") { // an IPv6 address, kept as written
		return strings.TrimPrefix(u.Host, "www.")
	}
	if shown, err := idna.ToUnicode(host); err == nil && !strings.ContainsFunc(shown, rightToLeft) {
		host = shown
	}
	if port := u.Port(); port != "" {
		host += ":" + port
	}
	return host
}

// rightToLeft reports whether r is a strong right-to-left letter, as
// Chrome's StringContainsStrongRTLChars counts them.
func rightToLeft(r rune) bool {
	p, _ := bidi.LookupRune(r)
	return p.Class() == bidi.R || p.Class() == bidi.AL
}
