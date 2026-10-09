// Package gauth reads Google Authenticator's "Transfer accounts" codes:
// otpauth-migration://offline?data=<base64>, where the data is a small
// protobuf message (MigrationPayload) listing the accounts.
package gauth

import (
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/bashhack/sesh/internal/totp"
	"github.com/bashhack/sesh/internal/vault"
)

// Type is an account's kind of code.
type Type string

// The kinds of code.
const (
	TypeTOTP    Type = "totp"
	TypeHOTP    Type = "hotp"
	TypeUnknown Type = "unknown"
)

// Account is one account in a transfer code.
type Account struct {
	// Secret is the account's key, in base32 as sesh stores TOTP keys.
	Secret string
	// Name is the account's label: "issuer:account" or just "account".
	Name   string
	Issuer string
	// Algorithm is SHA1, SHA256, SHA512, or MD5.
	Algorithm string
	Type      Type
	Digits    int
}

// Payload is one transfer code: its accounts, and which of a split
// export's codes it is (BatchIndex of BatchSize, from 0).
type Payload struct {
	Accounts   []Account
	BatchSize  int
	BatchIndex int
	BatchID    int
}

// Prefix starts every transfer code.
const Prefix = "otpauth-migration://"

// errDamaged is a transfer code whose data doesn't read.
var errDamaged = errors.New("the transfer code is damaged")

// Parse reads a transfer code's text.
func Parse(s string) (Payload, error) {
	if !strings.HasPrefix(s, Prefix) {
		return Payload{}, errors.New("this isn't a Google Authenticator transfer code (otpauth-migration://)")
	}
	// The data is read from the raw query: a "+" in it is base64, not a
	// space.
	_, raw, _ := strings.Cut(s, "?")
	var data string
	for part := range strings.SplitSeq(raw, "&") {
		if v, ok := strings.CutPrefix(part, "data="); ok {
			data = v
		}
	}
	data, err := url.PathUnescape(data)
	if err != nil || data == "" {
		return Payload{}, errors.New("the transfer code has no data")
	}
	b, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		if b, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(data, "=")); err != nil {
			return Payload{}, fmt.Errorf("%w: %v", errDamaged, err)
		}
	}
	return parsePayload(b)
}

// parsePayload reads MigrationPayload: 1 otp_parameters (repeated), 2
// version, 3 batch_size, 4 batch_index, 5 batch_id.
func parsePayload(b []byte) (Payload, error) {
	var p Payload
	err := fields(b, func(num int, varint uint64, bytes []byte) error {
		switch num {
		case 1:
			a, err := parseAccount(bytes)
			if err != nil {
				return err
			}
			p.Accounts = append(p.Accounts, a)
		case 3:
			p.BatchSize = int(varint) //nolint:gosec // a small count
		case 4:
			p.BatchIndex = int(varint) //nolint:gosec // a small count
		case 5:
			p.BatchID = int(varint) //nolint:gosec // an id, compared only
		}
		return nil
	})
	if err != nil {
		return Payload{}, err
	}
	if len(p.Accounts) == 0 {
		return Payload{}, fmt.Errorf("%w: it lists no accounts", errDamaged)
	}
	if p.BatchSize == 0 {
		p.BatchSize = 1
	}
	return p, nil
}

// parseAccount reads OtpParameters: 1 secret, 2 name, 3 issuer, 4
// algorithm, 5 digits, 6 type, 7 counter.
func parseAccount(b []byte) (Account, error) {
	a := Account{Algorithm: "SHA1", Digits: 6, Type: TypeTOTP}
	var secret []byte
	err := fields(b, func(num int, varint uint64, bytes []byte) error {
		switch num {
		case 1:
			secret = bytes
		case 2:
			a.Name = string(bytes)
		case 3:
			a.Issuer = string(bytes)
		case 4:
			a.Algorithm = map[uint64]string{0: "SHA1", 1: "SHA1", 2: "SHA256", 3: "SHA512", 4: "MD5"}[varint]
			if a.Algorithm == "" {
				a.Algorithm = fmt.Sprintf("unknown (%d)", varint)
			}
		case 5:
			switch varint {
			case 0, 1:
				a.Digits = 6
			case 2:
				a.Digits = 8
			default:
				a.Digits = 0
			}
		case 6:
			switch varint {
			case 0, 2:
				a.Type = TypeTOTP
			case 1:
				a.Type = TypeHOTP
			default:
				a.Type = TypeUnknown
			}
		}
		return nil
	})
	if err != nil {
		return Account{}, err
	}
	if len(secret) == 0 {
		return Account{}, fmt.Errorf("%w: an account has no secret", errDamaged)
	}
	a.Secret = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
	return a, nil
}

// fields calls f for each field of the protobuf message b: its number, and
// its value as a varint or as bytes. Fixed-size fields are skipped.
func fields(b []byte, f func(num int, varint uint64, bytes []byte) error) error {
	for len(b) > 0 {
		key, n := uvarint(b)
		if n <= 0 {
			return errDamaged
		}
		b = b[n:]
		num, wire := int(key>>3), key&7 //nolint:gosec // field numbers are small
		switch wire {
		case 0:
			v, n := uvarint(b)
			if n <= 0 {
				return errDamaged
			}
			b = b[n:]
			if err := f(num, v, nil); err != nil {
				return err
			}
		case 2:
			l, n := uvarint(b)
			if n <= 0 || l > uint64(len(b)-n) { //nolint:gosec // len(b)-n is never negative: n <= len(b)
				return errDamaged
			}
			v := b[n : n+int(l)] //nolint:gosec // checked against len(b) above
			b = b[n+int(l):]     //nolint:gosec // as above
			if err := f(num, 0, v); err != nil {
				return err
			}
		case 1:
			if len(b) < 8 {
				return errDamaged
			}
			b = b[8:]
		case 5:
			if len(b) < 4 {
				return errDamaged
			}
			b = b[4:]
		default:
			return errDamaged
		}
	}
	return nil
}

// uvarint reads a protobuf varint: its value, and how many bytes it took
// (0 or less if it doesn't read).
func uvarint(b []byte) (uint64, int) {
	var v uint64
	for i := 0; i < len(b) && i < 10; i++ {
		v |= uint64(b[i]&0x7f) << (7 * i)
		if b[i] < 0x80 {
			return v, i + 1
		}
	}
	return 0, -1
}

// Entry is the sesh TOTP entry for a: the issuer as its service name and
// the account as its username (without an "issuer:" prefix); with no
// issuer, the name's part before ":" is the service. Its code settings
// leave SHA1 and 6 digits as the defaults. skip says why sesh can't take
// it, "" when it can.
func (a *Account) Entry() (k vault.Key, params totp.Params, skip string) {
	switch {
	case a.Type == TypeHOTP:
		return k, params, "a counter-based (HOTP) code, which sesh doesn't make"
	case a.Type != TypeTOTP:
		return k, params, "an unknown kind of code"
	case a.Algorithm != "SHA1" && a.Algorithm != "SHA256" && a.Algorithm != "SHA512":
		return k, params, "uses " + a.Algorithm + ", which sesh doesn't support"
	case a.Digits != 6 && a.Digits != 8:
		return k, params, "an unknown number of digits"
	}
	service, user := a.Issuer, a.Name
	if before, after, ok := strings.Cut(a.Name, ":"); ok {
		if service == "" {
			service = before
		}
		if service == before {
			user = after
		}
	}
	service, user = strings.TrimSpace(service), strings.TrimSpace(user)
	if service == "" {
		service, user = user, ""
	}
	if service == "" {
		return k, params, "has no name"
	}
	k = vault.Key{Kind: vault.KindTOTP, Service: service, Username: user}
	if err := k.Validate(); err != nil {
		return vault.Key{}, params, err.Error()
	}
	params.Issuer = a.Issuer
	if a.Algorithm != "SHA1" {
		params.Algorithm = a.Algorithm
	}
	if a.Digits != 6 {
		params.Digits = a.Digits
	}
	return k, params, ""
}
