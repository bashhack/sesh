package bitwarden

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/importer"
)

// The fixtures in testdata are genuine exports of one throwaway vault, made
// with Bitwarden's CLI (bw 2026.9.1) against a local Vaultwarden:
// plain.json (--format json), password.json (--format encrypted_json
// --password export-pass-1; PBKDF2, the account's setting then), and
// account.json (--format encrypted_json). password-argon2id.json is the
// same vault after the account's KDF was set to Argon2id in the web vault
// (--password export-pass-argon). The values in them are made up.

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
	argon, err := Parse(read(t, "password-argon2id.json"), password("export-pass-argon"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plain, argon) {
		t.Error("the Argon2id export isn't the plain one")
	}
	if _, err := Parse(read(t, "password-argon2id.json"), password("export-pass-1")); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("Argon2id, wrong password: %v", err)
	}
	if _, err := Parse(read(t, "password.json"), password("wrong")); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("wrong password: %v", err)
	}
	if _, err := Parse(read(t, "account.json"), noPassword); !errors.Is(err, ErrAccountRestricted) {
		t.Errorf("account restricted: %v", err)
	}
}

// seal protects plain with pw as Bitwarden's password-protected export
// does (PBKDF2, 5000 iterations), for exports the CLI can't make here.
func seal(t *testing.T, pw string, plain []byte) []byte {
	t.Helper()
	salt := base64.StdEncoding.EncodeToString([]byte("sixteen byte slt"))
	key, err := pbkdf2.Key(sha256.New, pw, []byte(salt), 5000, 32)
	if err != nil {
		t.Fatal(err)
	}
	encKey, err := hkdf.Expand(sha256.New, key, "enc", 32)
	if err != nil {
		t.Fatal(err)
	}
	macKey, err := hkdf.Expand(sha256.New, key, "mac", 32)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		t.Fatal(err)
	}
	encString := func(b []byte) string {
		n := aes.BlockSize - len(b)%aes.BlockSize
		b = append(bytes.Clone(b), bytes.Repeat([]byte{byte(n)}, n)...)
		iv := make([]byte, aes.BlockSize)
		rand.Read(iv)
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(b, b)
		h := hmac.New(sha256.New, macKey)
		h.Write(iv)
		h.Write(b)
		enc := base64.StdEncoding.EncodeToString
		return "2." + enc(iv) + "|" + enc(b) + "|" + enc(h.Sum(nil))
	}
	out, err := json.Marshal(map[string]any{
		"encrypted": true, "passwordProtected": true, "salt": salt, "kdfType": 0, "kdfIterations": 5000,
		"encKeyValidation_DO_NOT_EDIT": encString([]byte("check")), "data": encString(plain),
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// An organization's export is refused, plain or protected; a protected
// export whose data was changed is damaged.
func TestParse_Refused(t *testing.T) {
	org := []byte(`{"encrypted":false,"collections":[{"id":"c1","organizationId":"o1","name":"Team"}],"items":[]}`)
	if _, err := Parse(org, noPassword); !errors.Is(err, errOrganization) {
		t.Errorf("organization, plain: %v", err)
	}
	if _, err := Parse(seal(t, "pw", org), password("pw")); !errors.Is(err, errOrganization) {
		t.Errorf("organization, protected: %v", err)
	}
	if _, err := Parse(seal(t, "pw", read(t, "plain.json")), password("pw")); err != nil {
		t.Errorf("sealed personal export: %v", err)
	}
	var env map[string]any
	if err := json.Unmarshal(read(t, "password.json"), &env); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(env["data"].(string), "|")
	ct, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	ct[0] ^= 1
	parts[1] = base64.StdEncoding.EncodeToString(ct)
	env["data"] = strings.Join(parts, "|")
	tampered, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(tampered, password("export-pass-1")); err == nil || !strings.Contains(err.Error(), "damaged") {
		t.Errorf("tampered data: %v", err)
	}
}

// Settings outside what sesh accepts are refused before any work, and
// before the password is asked for.
func TestParse_KDFBounds(t *testing.T) {
	for name, env := range map[string]string{
		"pbkdf2":  `{"encrypted":true,"passwordProtected":true,"salt":"c2FsdA==","kdfType":0,"kdfIterations":2000000000,"encKeyValidation_DO_NOT_EDIT":"2.a|b|c","data":"2.a|b|c"}`,
		"argon2":  `{"encrypted":true,"passwordProtected":true,"salt":"c2FsdA==","kdfType":1,"kdfIterations":3,"kdfMemory":1000000,"kdfParallelism":4,"encKeyValidation_DO_NOT_EDIT":"2.a|b|c","data":"2.a|b|c"}`,
		"unknown": `{"encrypted":true,"passwordProtected":true,"salt":"c2FsdA==","kdfType":7,"kdfIterations":3,"encKeyValidation_DO_NOT_EDIT":"2.a|b|c","data":"2.a|b|c"}`,
	} {
		if _, err := Parse([]byte(env), noPassword); err == nil || !strings.Contains(err.Error(), "sesh doesn't") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if !IsExport(read(t, "plain.json")) || !IsExport(read(t, "password.json")) || IsExport([]byte(`{"a":1}`)) {
		t.Error("IsExport")
	}
}

// The CSV export of the vault plain.json holds gives the same entries, less what a CSV doesn't carry: dates, old passwords, cards and the like, and which fields were hidden (all are kept secret).
func TestParseCSV(t *testing.T) {
	csvExp, err := Parse(read(t, "vault.csv"), noPassword)
	if err != nil {
		t.Fatal(err)
	}
	jsonExp, err := Parse(read(t, "plain.json"), noPassword)
	if err != nil {
		t.Fatal(err)
	}
	fromCSV, fromJSON := map[string]*importer.Entry{}, map[string]*importer.Entry{}
	for _, e := range Entries(&csvExp) {
		if e.Skip == "" {
			fromCSV[e.Key.String()] = e
		}
	}
	for _, e := range Entries(&jsonExp) {
		if e.Skip == "" {
			fromJSON[e.Key.String()] = e
		}
	}
	if len(fromCSV) == 0 {
		t.Fatal("nothing read from the CSV")
	}
	for k, c := range fromCSV {
		j, ok := fromJSON[k]
		if !ok {
			t.Errorf("%s: from the CSV, not the JSON", k)
			continue
		}
		if string(c.Secret) != string(j.Secret) || c.Folder != j.Folder || c.Details.URL != j.Details.URL || string(c.Details.Notes) != string(j.Details.Notes) || !slices.Equal(c.Tags, j.Tags) {
			t.Errorf("%s: CSV %+v\nJSON %+v", k, c, j)
		}
		if len(c.Earlier) != 0 || !c.Created.IsZero() {
			t.Errorf("%s: a CSV has no history or dates: %+v", k, c)
		}
		if len(c.Details.Fields) != len(j.Details.Fields) {
			t.Errorf("%s: fields %+v, want %+v", k, c.Details.Fields, j.Details.Fields)
			continue
		}
		for i, f := range c.Details.Fields {
			// A further URL is a plain field, as from JSON; a custom one is secret.
			custom := !strings.HasPrefix(f.Name, "url-")
			if f.Name != j.Details.Fields[i].Name || string(f.Value) != string(j.Details.Fields[i].Value) || f.Secret != custom {
				t.Errorf("%s: field %+v, want %+v, secret %v", k, f, j.Details.Fields[i], custom)
			}
		}
	}
	// Each of the CSV's rows: logins (with their TOTP keys) and the note.
	for _, k := range []string{"password/a-b site/u", "password/AWS console/root", "totp/AWS console/root", "password/GitHub/alice", "totp/GitHub/alice", "password/Router", "password/Steam/gamer", "secure_note/Wifi"} {
		if _, ok := fromCSV[k]; !ok {
			t.Errorf("%s not read from the CSV; read: %v", k, slices.Collect(maps.Keys(fromCSV)))
		}
	}
}

// A row's type decides what it is: a note stays one, whatever else the row has.
func TestParseCSVTypes(t *testing.T) {
	exp, err := Parse([]byte("folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n,,note,Door,code 1234,,0,,,stray,\n,,login,Shop,,,0,,me,shop-pw,\n"), noPassword)
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, e := range Entries(&exp) {
		keys = append(keys, e.Key.String())
	}
	if want := []string{"secure_note/Door", "password/Shop/me"}; !slices.Equal(keys, want) {
		t.Errorf("keys %q, want %q", keys, want)
	}
}

// An organization's CSV is refused, saying how to export one's own vault; a damaged one says so.
func TestParseCSVRefused(t *testing.T) {
	if _, err := Parse([]byte("collections,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n"), noPassword); !errors.Is(err, errOrganization) {
		t.Errorf("an organization's CSV: %v", err)
	}
	if _, err := Parse([]byte("folder,favorite,type,name,notes\n,,login,\"unclosed\n"), noPassword); err == nil || !strings.Contains(err.Error(), "can't be read") {
		t.Errorf("a damaged CSV: %v", err)
	}
}
