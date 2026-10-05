package main

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/config"
)

func TestTakeSettingFlags(t *testing.T) {
	tests := map[string]struct {
		want       config.Overrides
		wantErr    string
		args, rest []string
	}{
		"none": {
			args: []string{"sesh", "-service", "totp"},
			rest: []string{"sesh", "-service", "totp"},
		},
		"each form, anywhere": {
			args: []string{"sesh", "--key-source", "password", "-service", "password", "-action", "list", "-db-path=/v/s.db"},
			rest: []string{"sesh", "-service", "password", "-action", "list"},
			want: config.Overrides{KeySource: "password", DBPath: "/v/s.db"},
		},
		"before a subcommand": {
			args: []string{"sesh", "--db-path", "/v/s.db", "config"},
			rest: []string{"sesh", "config"},
			want: config.Overrides{DBPath: "/v/s.db"},
		},
		"after -- is left alone": {
			args: []string{"sesh", "-service", "x", "--", "--key-source", "password"},
			rest: []string{"sesh", "-service", "x", "--", "--key-source", "password"},
		},
		"value that isn't a flag": {
			args: []string{"sesh", "-service-name", "key-source"},
			rest: []string{"sesh", "-service-name", "key-source"},
		},
		"--backend isn't a setting any more": {
			args: []string{"sesh", "--backend", "sqlite", "-service", "x"},
			rest: []string{"sesh", "--backend", "sqlite", "-service", "x"},
		},
		"missing value at the end": {args: []string{"sesh", "--key-source"}, wantErr: "--key-source needs a value"},
		"empty value":              {args: []string{"sesh", "--db-path="}, wantErr: "--db-path needs a value"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			rest, got, err := takeSettingFlags(tt.args)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(rest, tt.rest) || got != tt.want {
				t.Errorf("got rest %q, overrides %+v; want %q, %+v", rest, got, tt.rest, tt.want)
			}
		})
	}
}

func TestSettingFlags_ReachSettingsAndConfigOutput(t *testing.T) {
	useConfigFile(t, "key_source = \"keychain\"\n")
	orig := cliOverrides
	t.Cleanup(func() { cliOverrides = orig })
	var err error
	if _, cliOverrides, err = takeSettingFlags([]string{"sesh", "--key-source", "password", "--db-path", "/tmp/flag/vault.db"}); err != nil {
		t.Fatal(err)
	}

	app := agentTestApp()
	if err := runConfig(app, nil); err != nil {
		t.Fatal(err)
	}
	got := app.Stdout.(*bytes.Buffer).String()
	for _, want := range []string{"key_source            password      (flag: --key-source)", "db_path               /tmp/flag/vault.db\n                      (flag: --db-path)"} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}

	if _, cliOverrides, err = takeSettingFlags([]string{"sesh", "--key-source", "pass"}); err != nil {
		t.Fatal(err)
	}
	if _, err := settings(); err == nil || !strings.Contains(err.Error(), `--key-source = "pass"`) {
		t.Errorf("err = %v, want the bad flag value named", err)
	}
}

func TestSettingFlags_ValidatedOnTheirOwn(t *testing.T) {
	for name, tt := range map[string]struct {
		wantSub string
		args    []string
	}{
		"bad key source before --version": {`--key-source = "bogus": want "password" or "keychain"`, []string{"sesh", "--key-source", "bogus", "--version"}},
		"flag taken as a value":           {`--key-source = "--version"`, []string{"sesh", "--key-source", "--version"}},
		"flag taken as a path":            {`--db-path = "--list": want an absolute path`, []string{"sesh", "--db-path", "--list"}},
	} {
		t.Run(name, func(t *testing.T) {
			_, o, err := takeSettingFlags(tt.args)
			if err == nil {
				err = o.Validate()
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantSub) {
				t.Fatalf("err = %v, want %q", err, tt.wantSub)
			}
		})
	}
	if _, o, err := takeSettingFlags([]string{"sesh", "--key-source=password", "--db-path", "~/v.db"}); err != nil || o.Validate() != nil {
		t.Errorf("valid flags rejected: %v / %v", err, o.Validate())
	}
}
