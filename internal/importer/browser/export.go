// Package browser reads web browsers' password exports: Chrome's, and
// that of other browsers built on Chromium that write the same columns,
// and Firefox's. The formats follow the browsers' own code (Chromium's
// components/password_manager/core/browser/export/password_csv_writer.cc,
// Firefox's toolkit/components/passwordmgr/LoginExport.sys.mjs), and are
// tested against exports made by Chromium and Firefox.
package browser

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The browsers whose exports are read, as sesh import --from names them.
const (
	Chrome  = "chrome"
	Firefox = "firefox"
)

// Login is one saved password.
type Login struct {
	Created time.Time
	Updated time.Time
	// Name is Chrome's name for the site or app; Firefox has none.
	Name     string
	URL      string
	Username string
	Password string
	Note     string
	// Realm is a Firefox login's HTTP authentication realm, "" for a
	// login form's.
	Realm string
}

// Export is the logins of one browser's export.
type Export struct {
	Browser string
	Logins  []Login
}

// The columns each browser writes, in order, as its header names them.
// Chrome wrote no note column before 123, when the notes feature flag
// went (password_csv_writer.cc, chromium 172cae75).
var (
	chromeColumns    = []string{"name", "url", "username", "password", "note"}
	oldChromeColumns = chromeColumns[:4]
	firefoxColumns   = []string{"url", "username", "password", "httpRealm", "formActionOrigin", "guid", "timeCreated", "timeLastUsed", "timePasswordChanged"}
)

// Detect is the browser whose export b is, by its header, or "".
func Detect(b []byte) string {
	header, err := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(b, []byte("\ufeff")))).Read()
	switch {
	case err != nil:
		return ""
	case slices.Equal(header, chromeColumns), slices.Equal(header, oldChromeColumns):
		return Chrome
	case slices.Equal(header, firefoxColumns):
		return Firefox
	}
	return ""
}

// Parse reads a browser's password export. A line break inside a quoted
// value is read as "\n", whether the file has "\n" or "\r\n" there.
func Parse(b []byte) (Export, error) {
	which := Detect(b)
	if which == "" {
		return Export{}, errors.New("this isn't a Chrome or Firefox password export: its first line isn't one of their headers")
	}
	r := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(b, []byte("\ufeff"))))
	r.FieldsPerRecord = -1
	exp := Export{Browser: which}
	line, columns := 0, 0
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Export{}, fmt.Errorf("this %s export is damaged: %w", title(which), err)
		}
		line++
		if line == 1 {
			columns = len(rec) // the header
			continue
		}
		var l Login
		switch which {
		case Chrome:
			if len(rec) != columns {
				return Export{}, fmt.Errorf("this Chrome export is damaged: login %d has %d columns, not %d", line-1, len(rec), columns)
			}
			l = Login{Name: rec[0], URL: rec[1], Username: rec[2], Password: rec[3]}
			if columns == len(chromeColumns) {
				l.Note = rec[4]
			}
		case Firefox:
			if len(rec) != len(firefoxColumns) {
				return Export{}, fmt.Errorf("this Firefox export is damaged: login %d has %d columns, not %d", line-1, len(rec), len(firefoxColumns))
			}
			l = Login{URL: rec[0], Username: rec[1], Password: rec[2], Realm: rec[3]}
			if l.Created, err = millis(rec[6]); err == nil {
				l.Updated, err = millis(rec[8])
			}
			if err != nil {
				return Export{}, fmt.Errorf("this Firefox export is damaged: login %d: %w", line-1, err)
			}
		}
		exp.Logins = append(exp.Logins, l)
	}
	return exp, nil
}

// millis reads a Firefox time, milliseconds since 1970; "" is none.
func millis(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("a time doesn't read: %q", s)
	}
	return time.UnixMilli(n).UTC(), nil
}

// title is a browser's name as messages give it.
func title(which string) string {
	if which == Firefox {
		return "Firefox"
	}
	return strings.ToUpper(which[:1]) + which[1:]
}

// Title is the browser's name as messages give it.
func (e *Export) Title() string { return title(e.Browser) }
