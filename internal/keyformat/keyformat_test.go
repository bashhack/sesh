package keyformat

import (
	"testing"
)

func TestBuild(t *testing.T) {
	tests := map[string]struct {
		namespace string
		expected  string
		segments  []string
		wantErr   bool
	}{
		"no segments": {
			namespace: "sesh-mfa",
			segments:  nil,
			expected:  "sesh-mfa",
		},
		"single segment": {
			namespace: "sesh-aws",
			segments:  []string{"production"},
			expected:  "sesh-aws/production",
		},
		"two segments": {
			namespace: "sesh-totp",
			segments:  []string{"github", "personal"},
			expected:  "sesh-totp/github/personal",
		},
		"three segments": {
			namespace: "sesh-password",
			segments:  []string{"password", "stripe", "alice"},
			expected:  "sesh-password/password/stripe/alice",
		},
		"segments with dashes are fine": {
			namespace: "sesh-totp",
			segments:  []string{"github-prod", "work-account"},
			expected:  "sesh-totp/github-prod/work-account",
		},
		"segment with slash is rejected": {
			namespace: "sesh-aws",
			segments:  []string{"bad/segment"},
			wantErr:   true,
		},
		"slash in later segment is rejected": {
			namespace: "sesh-password",
			segments:  []string{"password", "ok", "bad/name"},
			wantErr:   true,
		},
		"empty segment is rejected": {
			namespace: "sesh-password",
			segments:  []string{"password", "", "alice"},
			wantErr:   true,
		},
		"single empty segment is rejected": {
			namespace: "sesh-aws",
			segments:  []string{""},
			wantErr:   true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := Build(tc.namespace, tc.segments...)
			if tc.wantErr {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, got)
			}
		})
	}
}

func TestMustBuild(t *testing.T) {
	t.Run("valid input", func(t *testing.T) {
		got := MustBuild("sesh-aws", "production")
		if got != "sesh-aws/production" {
			t.Errorf("expected %q, got %q", "sesh-aws/production", got)
		}
	})

	t.Run("invalid input panics", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("expected panic but did not get one")
			}
		}()
		MustBuild("sesh-aws", "bad/segment")
	})
}

func TestParse(t *testing.T) {
	tests := map[string]struct {
		key       string
		namespace string
		expected  []string
		wantErr   bool
	}{
		"single segment": {
			key:       "sesh-aws/production",
			namespace: "sesh-aws",
			expected:  []string{"production"},
		},
		"two segments": {
			key:       "sesh-totp/github/personal",
			namespace: "sesh-totp",
			expected:  []string{"github", "personal"},
		},
		"three segments": {
			key:       "sesh-password/password/stripe/alice",
			namespace: "sesh-password",
			expected:  []string{"password", "stripe", "alice"},
		},
		"no segments returns nil": {
			key:       "sesh-mfa",
			namespace: "sesh-mfa",
			expected:  nil,
		},
		"wrong namespace": {
			key:       "sesh-totp/github",
			namespace: "sesh-aws",
			wantErr:   true,
		},
		"namespace prefix without slash": {
			key:       "sesh-aws-serial/prod",
			namespace: "sesh-aws",
			wantErr:   true,
		},
		"empty after namespace": {
			key:       "sesh-aws/",
			namespace: "sesh-aws",
			wantErr:   true,
		},
		"consecutive slashes rejected": {
			key:       "sesh-aws//production",
			namespace: "sesh-aws",
			wantErr:   true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := Parse(tc.key, tc.namespace)
			if tc.wantErr {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tc.expected) {
				t.Fatalf("expected %d segments, got %d", len(tc.expected), len(got))
			}
			for i, seg := range got {
				if seg != tc.expected[i] {
					t.Errorf("segment %d: expected %q, got %q", i, tc.expected[i], seg)
				}
			}
		})
	}
}

func TestBuildParseRoundTrip(t *testing.T) {
	tests := map[string]struct {
		namespace string
		segments  []string
	}{
		"aws key": {
			namespace: "sesh-aws",
			segments:  []string{"production"},
		},
		"totp with profile": {
			namespace: "sesh-totp",
			segments:  []string{"github-enterprise", "work"},
		},
		"password entry": {
			namespace: "sesh-password",
			segments:  []string{"api_key", "my-service", "admin-user"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			key, err := Build(tc.namespace, tc.segments...)
			if err != nil {
				t.Fatalf("Build failed: %v", err)
			}
			got, err := Parse(key, tc.namespace)
			if err != nil {
				t.Fatalf("Parse failed: %v", err)
			}
			if len(got) != len(tc.segments) {
				t.Fatalf("expected %d segments, got %d", len(tc.segments), len(got))
			}
			for i, seg := range got {
				if seg != tc.segments[i] {
					t.Errorf("segment %d: expected %q, got %q", i, tc.segments[i], seg)
				}
			}
		})
	}
}
