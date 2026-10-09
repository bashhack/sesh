package qrcode

import (
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/makiuchi-d/gozxing"
	zqr "github.com/makiuchi-d/gozxing/qrcode"
)

// qrImage draws text as a QR code with a white border.
func qrImage(t *testing.T, text string) image.Image {
	t.Helper()
	m, err := zqr.NewQRCodeWriter().Encode(text, gozxing.BarcodeFormat_QR_CODE, 400, 400, nil)
	if err != nil {
		t.Fatal(err)
	}
	img := image.NewGray(image.Rect(0, 0, 400, 400))
	for y := range 400 {
		for x := range 400 {
			c := color.Gray{Y: 255}
			if m.Get(x, y) {
				c = color.Gray{}
			}
			img.SetGray(x, y, c)
		}
	}
	return img
}

// The text of a QR code is read from a PNG or a JPEG.
func TestReadTextsFromFile(t *testing.T) {
	const text = "otpauth-migration://offline?data=CjEKCkhlbGxv"
	dir := t.TempDir()
	img := qrImage(t, text)
	for name, write := range map[string]func(*os.File) error{
		"code.png": func(f *os.File) error { return png.Encode(f, img) },
		"code.JPG": func(f *os.File) error { return jpeg.Encode(f, img, &jpeg.Options{Quality: 90}) },
	} {
		path := filepath.Join(dir, name)
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := write(f); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		if got, err := ReadTextsFromFile(path); err != nil || len(got) != 1 || got[0] != text {
			t.Errorf("%s: %q, %v", name, got, err)
		}
	}
	heic := filepath.Join(dir, "IMG_1.HEIC")
	if err := os.WriteFile(heic, []byte("\x00\x00\x00\x18ftypheic"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadTextsFromFile(heic); err == nil || !strings.Contains(err.Error(), "sips -s format png") {
		t.Errorf("HEIC: %v", err)
	}
	blank := filepath.Join(dir, "blank.png")
	f, err := os.Create(blank)
	if err != nil {
		t.Fatal(err)
	}
	if err := png.Encode(f, image.NewGray(image.Rect(0, 0, 50, 50))); err != nil {
		t.Fatal(err)
	}
	_ = f.Close() //nolint:errcheck // written
	if _, err := ReadTextsFromFile(blank); err == nil || !strings.Contains(err.Error(), "no QR code found in") {
		t.Errorf("blank: %v", err)
	}
}

// invert returns img light-on-dark.
func invert(img image.Image) image.Image {
	b := img.Bounds()
	out := image.NewGray(b)
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			g := color.GrayModel.Convert(img.At(x, y)).(color.Gray)
			out.SetGray(x, y, color.Gray{Y: 255 - g.Y})
		}
	}
	return out
}

// photo enlarges img by f and blurs it, as a full-size phone photo of a
// screen comes out.
func photo(img image.Image, f, blur int) image.Image {
	b := img.Bounds()
	big := image.NewGray(image.Rect(0, 0, b.Dx()*f, b.Dy()*f))
	for y := range big.Bounds().Dy() {
		for x := range big.Bounds().Dx() {
			big.SetGray(x, y, color.GrayModel.Convert(img.At(x/f, y/f)).(color.Gray))
		}
	}
	out := image.NewGray(big.Bounds())
	for y := range big.Bounds().Dy() {
		for x := range big.Bounds().Dx() {
			sum, n := 0, 0
			for dy := -blur; dy <= blur; dy += 2 {
				for dx := -blur; dx <= blur; dx += 2 {
					if p := (image.Point{x + dx, y + dy}); p.In(big.Bounds()) {
						sum += int(big.GrayAt(p.X, p.Y).Y)
						n++
					}
				}
			}
			out.SetGray(x, y, color.Gray{Y: uint8(sum / n)})
		}
	}
	return out
}

// Codes are read light on dark too, from a full-size blurred photo, and
// every code in an image, not just one.
func TestReadTexts_Hard(t *testing.T) {
	a, b := "otpauth-migration://offline?data=AAAA", "otpauth-migration://offline?data=BBBB"
	if got, err := ReadTexts(invert(qrImage(t, a))); err != nil || len(got) != 1 || got[0] != a {
		t.Errorf("inverted: %q, %v", got, err)
	}
	if got, err := ReadTexts(photo(qrImage(t, a), 9, 12)); err != nil || len(got) != 1 || got[0] != a {
		t.Errorf("a blurred photo: %q, %v", got, err)
	}
	two := image.NewGray(image.Rect(0, 0, 900, 400))
	for y := range 400 {
		for x := range 900 {
			two.SetGray(x, y, color.Gray{Y: 255})
		}
	}
	for i, img := range []image.Image{qrImage(t, a), qrImage(t, b)} {
		for y := range 400 {
			for x := range 400 {
				two.Set(x+i*500, y, img.At(x, y))
			}
		}
	}
	got, err := ReadTexts(two)
	slices.Sort(got)
	if err != nil || len(got) != 2 || got[0] != a || got[1] != b {
		t.Errorf("two codes: %q, %v", got, err)
	}
}
