package importer

import (
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/vault"
)

func TestFitFolder(t *testing.T) {
	for in, want := range map[string]string{
		"Work Accounts":         "Work-Accounts",
		"Work Accounts/Banking": "Work-Accounts/Banking",
		"Bank & Co":             "Bank-Co",
		"/Social/Forums/":       "Social/Forums",
		"Café":                  "Café",
		"a//b":                  "a/b",
		"-lead/...":             "lead",
		"":                      "",
		"🔒 Secure":              "Secure",
	} {
		if got := FitFolder(in); got != want || (got != "" && vault.CheckFolder(got) != nil) {
			t.Errorf("FitFolder(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFitFieldName(t *testing.T) {
	for in, want := range map[string]string{
		"2fa enabled":            "2fa-enabled",
		"recovery-email":         "recovery-email",
		"url":                    "url-field",
		"Notes":                  "Notes-field",
		"???":                    "field",
		strings.Repeat("x", 100): strings.Repeat("x", vault.MaxFieldNameLength-6),
	} {
		if got := FitFieldName(in); got != want || vault.CheckFieldName(got) != nil {
			t.Errorf("FitFieldName(%q) = %q (%v), want %q", in, got, vault.CheckFieldName(got), want)
		}
	}
}

func TestFitName(t *testing.T) {
	for in, want := range map[string]string{
		"a/b site":  "a-b site",
		" GitHub ":  "GitHub",
		"x\u200by":  "xy",
		"tab\there": "tabhere",
	} {
		if got := FitName(in); got != want || vault.CheckName("service", got) != nil {
			t.Errorf("FitName(%q) = %q, want %q", in, got, want)
		}
	}
}
