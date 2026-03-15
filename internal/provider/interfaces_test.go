package provider

import (
	"testing"
	"time"
)

func TestClock_TimeNow(t *testing.T) {
	tests := map[string]struct {
		nowFunc  func() time.Time
		wantTime time.Time
	}{
		"uses custom Now when set": {
			nowFunc:  func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) },
			wantTime: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		"uses time.Now when nil": {
			nowFunc: nil,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			c := &Clock{Now: tc.nowFunc}
			got := c.TimeNow()
			if tc.nowFunc != nil {
				if !got.Equal(tc.wantTime) {
					t.Errorf("TimeNow() = %v, want %v", got, tc.wantTime)
				}
			} else {
				// Should be close to current time
				if time.Since(got) > time.Second {
					t.Errorf("TimeNow() = %v, expected close to now", got)
				}
			}
		})
	}
}

func TestClock_SecondsLeftInWindow(t *testing.T) {
	tests := map[string]struct {
		unixTime    int64
		wantSeconds int64
	}{
		"start of window": {
			unixTime:    0,
			wantSeconds: 30,
		},
		"middle of window": {
			unixTime:    15,
			wantSeconds: 15,
		},
		"near end of window": {
			unixTime:    29,
			wantSeconds: 1,
		},
		"exact boundary": {
			unixTime:    30,
			wantSeconds: 30,
		},
		"arbitrary time": {
			unixTime:    1234567890,
			wantSeconds: 30 - (1234567890 % 30),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			c := &Clock{Now: func() time.Time { return time.Unix(tc.unixTime, 0) }}
			got := c.SecondsLeftInWindow()
			if got != tc.wantSeconds {
				t.Errorf("SecondsLeftInWindow() = %d, want %d", got, tc.wantSeconds)
			}
		})
	}
}

func TestKeyUser_EnsureUser(t *testing.T) {
	tests := map[string]struct {
		initialUser string
		wantEmpty   bool
	}{
		"already set": {
			initialUser: "testuser",
			wantEmpty:   false,
		},
		"not set - looks up current user": {
			initialUser: "",
			wantEmpty:   false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			ku := &KeyUser{User: tc.initialUser}
			err := ku.EnsureUser()
			if err != nil {
				t.Fatalf("EnsureUser() error = %v", err)
			}
			if tc.initialUser != "" && ku.User != tc.initialUser {
				t.Errorf("EnsureUser() changed user from %q to %q", tc.initialUser, ku.User)
			}
			if ku.User == "" {
				t.Error("EnsureUser() left User empty")
			}
		})
	}
}

func TestParseEntryID(t *testing.T) {
	tests := map[string]struct {
		id          string
		wantService string
		wantAccount string
		wantErr     bool
	}{
		"valid entry": {
			id:          "github:user@example.com",
			wantService: "github",
			wantAccount: "user@example.com",
		},
		"colon in account": {
			id:          "service:account:extra",
			wantService: "service",
			wantAccount: "account:extra",
		},
		"no colon": {
			id:      "invalid",
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			service, account, err := ParseEntryID(tc.id)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParseEntryID() error = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr {
				if service != tc.wantService {
					t.Errorf("service = %q, want %q", service, tc.wantService)
				}
				if account != tc.wantAccount {
					t.Errorf("account = %q, want %q", account, tc.wantAccount)
				}
			}
		})
	}
}

func TestFormatClipboardDisplayInfo(t *testing.T) {
	got := FormatClipboardDisplayInfo("123456", "789012", 15, "TOTP code", "GitHub")
	want := "Current: 123456  |  Next: 789012  |  Time left: 15s\n🔑 TOTP code for GitHub"
	if got != want {
		t.Errorf("FormatClipboardDisplayInfo() = %q, want %q", got, want)
	}
}

func TestFormatRegularDisplayInfo(t *testing.T) {
	got := FormatRegularDisplayInfo("AWS credentials", "profile work")
	want := "🔑 AWS credentials for profile work"
	if got != want {
		t.Errorf("FormatRegularDisplayInfo() = %q, want %q", got, want)
	}
}

func TestCreateClipboardCredentials(t *testing.T) {
	creds := CreateClipboardCredentials("totp", "123456", "789012", 15, "TOTP code", "GitHub")

	if creds.Provider != "totp" {
		t.Errorf("Provider = %q, want %q", creds.Provider, "totp")
	}
	if creds.CopyValue != "123456" {
		t.Errorf("CopyValue = %q, want %q", creds.CopyValue, "123456")
	}
	if creds.ClipboardDescription != "TOTP code" {
		t.Errorf("ClipboardDescription = %q, want %q", creds.ClipboardDescription, "TOTP code")
	}
	if creds.MFAAuthenticated {
		t.Error("MFAAuthenticated should be false for clipboard mode")
	}
	if creds.Expiry.IsZero() {
		t.Error("Expiry should not be zero")
	}
	if len(creds.Variables) != 0 {
		t.Errorf("Variables should be empty, got %v", creds.Variables)
	}
}
