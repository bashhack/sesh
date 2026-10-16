package totp

import "testing"

func TestURI(t *testing.T) {
	for _, tt := range []struct {
		secret, issuer, account, want string
		p                             Params
	}{
		{"JBSW Y3DP EHPK 3PXP====", "GitHub", "alice", "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub", Params{}},
		{"jbswy3dpehpk3pxp", "", "bob@example.com", "otpauth://totp/bob@example.com?secret=JBSWY3DPEHPK3PXP", Params{Algorithm: "SHA1", Digits: 6, Period: 30}},
		{"JBSWY3DPEHPK3PXP", "Big Bank & Co", "me/1", "otpauth://totp/Big%20Bank%20&%20Co:me%2F1?secret=JBSWY3DPEHPK3PXP&issuer=Big+Bank+%26+Co&algorithm=SHA256&digits=8&period=60", Params{Algorithm: "sha256", Digits: 8, Period: 60}},
	} {
		if got := URI([]byte(tt.secret), tt.issuer, tt.account, tt.p); got != tt.want {
			t.Errorf("URI(%q, %q, %q, %+v)\n got %s\nwant %s", tt.secret, tt.issuer, tt.account, tt.p, got, tt.want)
		}
	}
}
