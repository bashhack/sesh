package config

import (
	"strings"
	"testing"
)

// Only a smaller, nonzero keep deletes; 0 keeps everything, and other settings delete nothing.
func TestLoss(t *testing.T) {
	for _, c := range []struct{ key, from, to, wantSub string }{
		{"history.keep", "10", "4", "beyond its newest 4"},
		{"history.keep", "0", "4", "beyond its newest 4"},
		{"trash.keep_days", "30", "1", "more than 1 day"},
		{"audit.retention_days", "365", "90", "older than 90 days"},
		{"backup.keep", "10", "3", "beyond the newest 3"},
		{"history.keep", "4", "10", ""},
		{"history.keep", "4", "0", ""},
		{"history.keep", "4", "4", ""},
		{"clipboard_timeout", "30", "10", ""},
		{"history.keep", "x", "4", ""},
	} {
		got := Loss(c.key, c.from, c.to)
		if c.wantSub == "" && got != "" || !strings.Contains(got, c.wantSub) {
			t.Errorf("Loss(%s, %s, %s) = %q, want %q", c.key, c.from, c.to, got, c.wantSub)
		}
	}
}
