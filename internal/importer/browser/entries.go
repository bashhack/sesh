package browser

import (
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/net/idna"

	"github.com/bashhack/sesh/internal/importer"
	"github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/vault"
)

// firefoxAccount is the address of Firefox's own sign-in to the user's
// Mozilla account (FxAccountsCommon.sys.mjs FXA_PWDMGR_HOST), which its
// export includes though its password manager hides it
// (LoginHelper.sys.mjs isUserFacingLogin).
const firefoxAccount = "chrome://FirefoxAccounts"

// Entries is the entries an export's logins become, in order: a password
// entry for each, and for the Passwords app's a TOTP entry beside it for
// its verification code (alone, with the details, when there's no
// password). Each is named for its site (see siteName), or the Passwords
// app's by its title, with the address as its URL. Two of one name and username get " (2)",
// unless, in Chrome's export, the password is the same too: Chrome writes
// a row for each address of one login, and the repeats are skipped. A
// login with neither a password nor a code is skipped, as is Firefox's
// sign-in to the Mozilla account.
func Entries(exp *Export) []*importer.Entry {
	names := importer.NewNames()
	type login struct{ site, user, password string }
	seen := map[login]bool{}
	var out []*importer.Entry
	for i := range exp.Logins {
		l := &exp.Logins[i]
		site := siteName(l, exp.Browser)
		if exp.Browser == ApplePasswords && importer.FitName(l.Title) != "" {
			site = l.Title
		}
		e := &importer.Entry{Name: site, Created: l.Created, Updated: l.Updated}
		service := importer.FitName(site)
		user := importer.FitName(l.Username)
		switch {
		case l.URL == firefoxAccount:
			e.Skip = "Firefox's own sign-in to your Mozilla account"
		case service == "":
			e.Skip = "it has no site"
		case l.Password == "" && l.OTPAuth == "":
			e.Skip = "it has no password"
		case exp.Browser == Chrome && seen[login{site, l.Username, l.Password}]:
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
		e.Details = vault.Details{URL: l.URL, Fields: fs.Fields}
		if l.Note != "" {
			e.Details.Notes = []byte(l.Note)
		}
		e.Changes = append(e.Changes, fs.Changes...)
		var item []*importer.Entry
		if l.Password != "" {
			p := *e
			p.Key = vault.Key{Kind: vault.KindPassword, Service: service, Username: user}
			p.Secret = []byte(l.Password)
			item = append(item, &p)
		}
		// The Passwords app's verification code is a TOTP entry beside the
		// password entry, with the details only where there's no password
		// entry.
		if l.OTPAuth != "" {
			t := *e
			t.Changes = slices.Clone(e.Changes)
			t.Key = vault.Key{Kind: vault.KindTOTP, Service: service, Username: user}
			if len(item) > 0 {
				t.Details = vault.Details{}
			}
			secret, params, why := totpKey(l.OTPAuth)
			if why != "" {
				t.Skip = "its verification code: " + why
			} else {
				t.Secret, t.Settings = []byte(secret), vault.Settings{TOTP: params}
			}
			item = append(item, &t)
		}
		importer.Place(item, names)
		out = append(out, item...)
	}
	return out
}

// totpKey reads a verification code, an otpauth://totp address as the
// Passwords app writes it
// (otpauth://totp?secret=…&algorithm=SHA1&digits=6&period=30, with or
// without a label). sesh refuses what it can't make codes for. A
// reason never repeats the key.
func totpKey(s string) (secret string, params totp.Params, why string) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || !strings.EqualFold(u.Scheme, "otpauth") {
		return "", params, "it doesn't read as an otpauth:// address"
	}
	switch strings.ToLower(u.Host) {
	case "totp":
	case "hotp":
		return "", params, "a counter-based (HOTP) code, which sesh doesn't make"
	default:
		return "", params, "it doesn't read as an otpauth:// address"
	}
	q := u.Query()
	if strings.EqualFold(q.Get("encoder"), "steam") {
		return "", params, "a Steam code, which sesh doesn't make"
	}
	switch alg := strings.ToUpper(q.Get("algorithm")); alg {
	case "", "SHA1":
	case "SHA256", "SHA512":
		params.Algorithm = alg
	default:
		return "", params, "it uses " + alg + ", which sesh doesn't support"
	}
	if d := q.Get("digits"); d != "" {
		n, err := strconv.Atoi(d)
		switch {
		case err != nil:
			return "", params, "its digits setting isn't a number"
		case n < 6 || n > 8:
			return "", params, fmt.Sprintf("it makes %d-digit codes, which sesh doesn't make", n)
		case n != 6:
			params.Digits = n
		}
	}
	if p := q.Get("period"); p != "" {
		n, err := strconv.Atoi(p)
		switch {
		case err != nil || n < 1:
			return "", params, "its period setting isn't a positive number"
		case n > totp.MaxTOTPPeriodSeconds:
			return "", params, fmt.Sprintf("it makes a new code every %d seconds, longer than sesh allows", n)
		case n != 30:
			params.Period = n
		}
	}
	params.Issuer = q.Get("issuer")
	if params.Issuer == "" {
		if issuer, _, ok := strings.Cut(strings.TrimPrefix(u.Path, "/"), ":"); ok {
			params.Issuer = strings.TrimSpace(issuer)
		}
	}
	if q.Get("secret") == "" {
		return "", params, "it has no key"
	}
	normalized, err := totp.ValidateAndNormalizeSecret(q.Get("secret"))
	switch {
	case err != nil && strings.Contains(err.Error(), "too short"):
		return "", params, "the key is too short to be safe"
	case err != nil:
		return "", params, "the key isn't a valid base32 key"
	}
	return normalized, params, ""
}

// siteName is what a login is named for:
//   - an Android app's (Chrome's android://hash@package/) as Chrome names
//     it, or, where it gave no name, as Chrome would: the package reversed
//     (affiliation_utils.cc GetAndroidPackageDisplayName);
//   - an address with a host, the host without a leading "www.", port
//     kept. An internationalised one is in Unicode only where Chrome's
//     own name for it is: Chrome shows Unicode only after its checks for
//     lookalike letters and right-to-left text (credential_ui_entry.cc
//     GetOrigin, elide_url.cc HostForDisplay, url_formatter.cc), which
//     sesh doesn't repeat, so a host Chrome kept as xn--, and every
//     Firefox one, stays so;
//   - anything else, Chrome's name for it, or the address itself.
func siteName(l *Login, browser string) string {
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
	port := ""
	if p := u.Port(); p != "" {
		port = ":" + p
	}
	if browser == Chrome && strings.Contains(host, "xn--") {
		// Chrome's name is the origin as it shows it, the scheme left out
		// for https (OMIT_CRYPTOGRAPHIC).
		shown := strings.TrimPrefix(strings.TrimPrefix(l.Name, u.Scheme+"://"), "www.")
		if unicode, err := idna.ToUnicode(host); err == nil && shown == unicode+port {
			return shown
		}
	}
	return host + port
}
