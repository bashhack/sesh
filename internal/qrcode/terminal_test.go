package qrcode

import (
	"image"
	"image/color"
	"regexp"
	"strings"
	"testing"

	"github.com/bashhack/sesh/internal/totp"
)

// A QR code drawn for the terminal reads back as the text it was made from.
func TestTerminal(t *testing.T) {
	const text = "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
	drawn, err := Terminal(text)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(drawn, "\x1b[30;107m") || !strings.HasSuffix(drawn, "\x1b[0m\n") {
		t.Errorf("not set dark on light: %q…", drawn[:20])
	}
	lines := strings.Split(strings.TrimSuffix(regexp.MustCompile("\x1b\\[[0-9;]*m").ReplaceAllString(drawn, ""), "\n"), "\n")
	// Each character is two modules, top and bottom; 4 pixels each.
	const px = 4
	w := len([]rune(lines[0]))
	img := image.NewGray(image.Rect(0, 0, w*px, len(lines)*2*px))
	for y, line := range lines {
		if len([]rune(line)) != w {
			t.Fatalf("line %d is %d wide, not %d", y, len([]rune(line)), w)
		}
		for x, r := range []rune(line) {
			top, bottom := r == '█' || r == '▀', r == '█' || r == '▄'
			for dy := range 2 * px {
				for dx := range px {
					c := color.Gray{Y: 255}
					if dy < px && top || dy >= px && bottom {
						c = color.Gray{}
					}
					img.SetGray(x*px+dx, y*2*px+dy, c)
				}
			}
		}
	}
	got, err := ReadTexts(img)
	if err != nil || len(got) != 1 || got[0] != text {
		t.Errorf("read back %q, %v", got, err)
	}
}

// A link sesh writes for a TOTP entry reads back as the entry it came from.
func TestURIReadsBack(t *testing.T) {
	link := totp.URI([]byte("JBSWY3DPEHPK3PXP"), "Big Bank & Co", "me@example.com", totp.Params{Algorithm: "SHA256", Digits: 8, Period: 60})
	info, err := ExtractTOTPFullInfo(link)
	want := TOTPInfo{Secret: "JBSWY3DPEHPK3PXP", Issuer: "Big Bank & Co", Account: "me@example.com", Algorithm: "SHA256", Digits: 8, Period: 60}
	if err != nil || info != want {
		t.Errorf("%s read back as %+v, %v", link, info, err)
	}
	// A colon in a name doesn't move where the account starts.
	link = totp.URI([]byte("JBSWY3DPEHPK3PXP"), "Corp:VPN", "bob:ops", totp.Params{})
	if info, err := ExtractTOTPFullInfo(link); err != nil || info.Issuer != "Corp:VPN" || info.Account != "bob:ops" {
		t.Errorf("%s read back as %+v, %v", link, info, err)
	}
}
