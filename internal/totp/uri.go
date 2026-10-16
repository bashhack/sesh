package totp

import (
	"net/url"
	"strconv"
	"strings"
)

// URI is the otpauth:// link an authenticator app takes for secret
// (base32): labelled issuer:account, with the issuer again as a parameter,
// and the algorithm, digits and period only where they aren't the usual
// SHA1, 6 and 30. The secret is written without padding or spaces, as the
// key URI format asks. The link holds the secret: it's shown only when
// asked for.
func URI(secret []byte, issuer, account string, p Params) string {
	// A colon in either is escaped: the one between them is where an app
	// splits the label.
	part := func(s string) string { return strings.ReplaceAll(url.PathEscape(s), ":", "%3A") }
	label := part(account)
	if issuer != "" {
		label = part(issuer) + ":" + label
	}
	key := strings.TrimRight(strings.ToUpper(strings.Join(strings.Fields(string(secret)), "")), "=")
	// Built by hand, in this order, as authenticators expect; base32 and
	// the parameters need no escaping but the issuer.
	q := "secret=" + key
	if issuer != "" {
		q += "&issuer=" + url.QueryEscape(issuer)
	}
	if p.Algorithm != "" && !strings.EqualFold(p.Algorithm, "SHA1") {
		q += "&algorithm=" + strings.ToUpper(p.Algorithm)
	}
	if p.Digits != 0 && p.Digits != 6 {
		q += "&digits=" + strconv.Itoa(p.Digits)
	}
	if p.Period != 0 && p.Period != 30 {
		q += "&period=" + strconv.Itoa(p.Period)
	}
	return "otpauth://totp/" + label + "?" + q
}

// Label is how an authenticator app labels a TOTP entry named service,
// with username: its issuer (the one its QR code or link gave, in p, or
// else its name) and its account (its username, or else its name).
func Label(service, username string, p Params) (issuer, account string) {
	issuer, account = p.Issuer, username
	if issuer == "" {
		issuer = service
	}
	if account == "" {
		account = service
	}
	return issuer, account
}

// LabelName is an authenticator app's name for an entry: "GitHub (alice)",
// or the issuer alone where the account is the same.
func LabelName(issuer, account string) string {
	if account == issuer {
		return issuer
	}
	return issuer + " (" + account + ")"
}
