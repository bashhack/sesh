package bitwarden

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

// The fixtures in testdata are genuine exports of one throwaway vault, made
// with Bitwarden's CLI (bw 2026.9.1) against a local Vaultwarden:
// plain.json (--format json), password.json (--format encrypted_json
// --password export-pass-1), and account.json (--format encrypted_json).
// The values in them are made up.

func read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func password(pw string) func() ([]byte, error) {
	return func() ([]byte, error) { return []byte(pw), nil }
}

func noPassword() ([]byte, error) {
	return nil, errors.New("asked for a password")
}

func TestParse_Plain(t *testing.T) {
	exp, err := Parse(read(t, "plain.json"), noPassword)
	if err != nil {
		t.Fatal(err)
	}
	if len(exp.Folders) != 5 || len(exp.Items) != 10 {
		t.Fatalf("%d folders, %d items", len(exp.Folders), len(exp.Items))
	}
	var gh *Item
	for i := range exp.Items {
		if exp.Items[i].Name == "GitHub" && exp.Items[i].Notes != "" {
			gh = &exp.Items[i]
		}
	}
	if gh == nil || gh.Login == nil || gh.Login.Username != "alice" || gh.Login.Password != "gh-new-password-2" ||
		len(gh.Login.URIs) != 2 || !strings.HasPrefix(gh.Login.TOTP, "otpauth://totp/GitHub:alice") ||
		len(gh.Fields) != 4 || gh.Fields[3].Type != FieldLinked || gh.Fields[3].Value != "" || len(gh.PasswordHistory) != 1 ||
		gh.CreationDate.IsZero() {
		t.Errorf("GitHub = %+v", gh)
	}
}

// The password-protected export opens with its password to the same
// export; a wrong one is refused, and the account-restricted one can't be
// opened at all.
func TestParse_Encrypted(t *testing.T) {
	plain, err := Parse(read(t, "plain.json"), noPassword)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Parse(read(t, "password.json"), password("export-pass-1"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plain, opened) {
		t.Error("the opened export isn't the plain one")
	}
	if _, err := Parse(read(t, "password.json"), password("wrong")); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("wrong password: %v", err)
	}
	if _, err := Parse(read(t, "account.json"), noPassword); !errors.Is(err, ErrAccountRestricted) {
		t.Errorf("account restricted: %v", err)
	}
}

// Settings outside what sesh accepts are refused before any work.
func TestParse_KDFBounds(t *testing.T) {
	for name, env := range map[string]string{
		"pbkdf2":  `{"encrypted":true,"passwordProtected":true,"salt":"c2FsdA==","kdfType":0,"kdfIterations":2000000000,"encKeyValidation_DO_NOT_EDIT":"2.a|b|c","data":"2.a|b|c"}`,
		"argon2":  `{"encrypted":true,"passwordProtected":true,"salt":"c2FsdA==","kdfType":1,"kdfIterations":3,"kdfMemory":1000000,"kdfParallelism":4,"encKeyValidation_DO_NOT_EDIT":"2.a|b|c","data":"2.a|b|c"}`,
		"unknown": `{"encrypted":true,"passwordProtected":true,"salt":"c2FsdA==","kdfType":7,"kdfIterations":3,"encKeyValidation_DO_NOT_EDIT":"2.a|b|c","data":"2.a|b|c"}`,
	} {
		if _, err := Parse([]byte(env), password("x")); err == nil || !strings.Contains(err.Error(), "sesh doesn't") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if !IsExport(read(t, "plain.json")) || !IsExport(read(t, "password.json")) || IsExport([]byte(`{"a":1}`)) {
		t.Error("IsExport")
	}
}
