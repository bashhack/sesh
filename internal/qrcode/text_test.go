package qrcode

import (
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"os"
	"path/filepath"
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
func TestReadTextFromFile(t *testing.T) {
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
		if got, err := ReadTextFromFile(path); err != nil || got != text {
			t.Errorf("%s: %q, %v", name, got, err)
		}
	}
	heic := filepath.Join(dir, "IMG_1.HEIC")
	if err := os.WriteFile(heic, []byte("\x00\x00\x00\x18ftypheic"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadTextFromFile(heic); err == nil || !strings.Contains(err.Error(), "sips -s format png") {
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
	if _, err := ReadTextFromFile(blank); err == nil || !strings.Contains(err.Error(), "no QR code found in") {
		t.Errorf("blank: %v", err)
	}
}
