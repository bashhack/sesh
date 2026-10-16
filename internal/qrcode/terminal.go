package qrcode

import (
	"fmt"
	"strings"

	"github.com/makiuchi-d/gozxing/qrcode/decoder"
	"github.com/makiuchi-d/gozxing/qrcode/encoder"
)

// quietZone is the light border, in modules, around a QR code drawn in
// the terminal: what a phone's camera needs to find its edges.
const quietZone = 2

// Terminal draws text as a QR code for a terminal: two rows of modules to
// a line, with half blocks, set dark on light whatever the terminal's own
// colors are, so a phone reads it on a dark theme too.
func Terminal(text string) (string, error) {
	code, err := encoder.Encoder_encodeWithoutHint(text, decoder.ErrorCorrectionLevel_M)
	if err != nil {
		return "", fmt.Errorf("make a QR code: %w", err)
	}
	m := code.GetMatrix()
	size := m.GetWidth()
	dark := func(x, y int) bool {
		x, y = x-quietZone, y-quietZone
		return x >= 0 && y >= 0 && x < size && y < size && m.Get(x, y) == 1
	}
	const (
		darkOnLight = "\x1b[30;107m"
		reset       = "\x1b[0m"
	)
	var b strings.Builder
	all := size + 2*quietZone
	for y := 0; y < all; y += 2 {
		b.WriteString(darkOnLight)
		for x := range all {
			top, bottom := dark(x, y), dark(x, y+1)
			switch {
			case top && bottom:
				b.WriteString("█")
			case top:
				b.WriteString("▀")
			case bottom:
				b.WriteString("▄")
			default:
				b.WriteByte(' ')
			}
		}
		b.WriteString(reset + "\n")
	}
	return b.String(), nil
}
