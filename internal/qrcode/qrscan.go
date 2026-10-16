// Package qrcode provides QR code scanning and decoding from screen captures.
package qrcode

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/color"
	_ "image/jpeg" // ReadTextFromFile reads JPEG photos
	"image/png"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/bashhack/sesh/internal/shell"

	"github.com/makiuchi-d/gozxing"
	multiqr "github.com/makiuchi-d/gozxing/multi/qrcode"
	"github.com/makiuchi-d/gozxing/qrcode"
)

var (
	execCommand = exec.Command
	osStat      = os.Stat
)

// DecodeQRCodeFromFile reads a QR code from an image file and extracts the TOTP secret
func DecodeQRCodeFromFile(filename string) (string, error) {
	file, err := os.Open(filename) //nolint:gosec // filename is trusted — internal callers provide controlled paths
	if err != nil {
		return "", fmt.Errorf("failed to open image file: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to close image file: %v\n", err)
		}
	}()

	img, err := png.Decode(file)
	if err != nil {
		return "", fmt.Errorf("failed to decode image: %w", err)
	}

	return DecodeQRCodeFromImage(img)
}

// DecodeQRCodeFromImage extracts TOTP secret from an image containing a QR code
func DecodeQRCodeFromImage(img image.Image) (string, error) {
	info, err := DecodeQRCodeFromImageFull(img)
	if err != nil {
		return "", err
	}
	return info.Secret, nil
}

// DecodeQRCodeFromImageFull extracts full TOTP info from a QR code image,
// including algorithm, digits, and period.
func DecodeQRCodeFromImageFull(img image.Image) (TOTPInfo, error) {
	bmp, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		return TOTPInfo{}, fmt.Errorf("failed to process image for QR reading: %w", err)
	}

	reader := qrcode.NewQRCodeReader()
	result, err := reader.Decode(bmp, nil)
	if err != nil {
		return TOTPInfo{}, fmt.Errorf("failed to decode QR code: %w\nMake sure the QR code is clearly visible in the screenshot", err)
	}

	return ExtractTOTPFullInfo(result.GetText())
}

// ScanQRCodeFull captures a QR code from screen and returns full TOTP info.
func ScanQRCodeFull() (TOTPInfo, error) {
	fmt.Println("📸 Please select the area containing the QR code...")
	text, err := CaptureText()
	if err != nil {
		return TOTPInfo{}, err
	}
	return ExtractTOTPFullInfo(text)
}

// CaptureText has the area of the screen with a QR code selected, as
// macOS's screencapture asks, and is the code's text. It prints nothing,
// so it can run under a full-screen app.
func CaptureText() (string, error) {
	tmp, err := os.CreateTemp("", "sesh-qr-*.png")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	tempFile := tmp.Name()
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("close temp file: %w", err)
	}
	defer os.Remove(tempFile) //nolint:errcheck // a temporary file, gone at the next reboot if not now

	cmd := execCommand("screencapture", "-i", tempFile)
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("failed to capture screenshot: %w", err)
	}
	fileInfo, err := osStat(tempFile)
	if err != nil || fileInfo.Size() < 100 {
		return "", errors.New("screenshot capture was canceled or failed")
	}

	file, err := os.Open(filepath.Clean(tempFile))
	if err != nil {
		return "", fmt.Errorf("failed to open screenshot: %w", err)
	}
	defer file.Close() //nolint:errcheck // read only
	img, err := png.Decode(file)
	if err != nil {
		return "", fmt.Errorf("failed to decode screenshot: %w", err)
	}
	bmp, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		return "", fmt.Errorf("failed to process image for QR reading: %w", err)
	}
	result, err := qrcode.NewQRCodeReader().Decode(bmp, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decode QR code: %w\nMake sure the QR code is clearly visible in the screenshot", err)
	}
	return result.GetText(), nil
}

// parseOTPAuth parses an otpauth://totp/ URI, in any case. The URI
// holds the secret, or is whatever else a QR code held, so no error quotes
// it, not even url.Parse's.
func parseOTPAuth(otpauthURL string) (*url.URL, error) {
	if !strings.HasPrefix(strings.ToLower(otpauthURL), "otpauth://") {
		return nil, errors.New("not a valid otpauth URL")
	}
	// url.Parse's errors, even unwrapped, can repeat part of the URI.
	parsedURL, err := url.Parse(otpauthURL)
	if err != nil {
		return nil, errors.New("failed to parse otpauth URL: it isn't a well-formed URL")
	}
	if !strings.EqualFold(parsedURL.Host, "totp") {
		if strings.EqualFold(parsedURL.Host, "hotp") {
			return nil, errors.New("unsupported OTP type HOTP (only TOTP is supported)")
		}
		return nil, errors.New("unsupported OTP type (only TOTP is supported)")
	}
	return parsedURL, nil
}

// ExtractSecretFromOTPAuthURL extracts just the secret from an otpauth
// URL. Only otpauth://totp/ URIs are accepted.
func ExtractSecretFromOTPAuthURL(otpauthURL string) (string, error) {
	parsedURL, err := parseOTPAuth(otpauthURL)
	if err != nil {
		return "", err
	}

	query := parsedURL.Query()
	secret := query.Get("secret")
	if secret == "" {
		return "", fmt.Errorf("no secret found in QR code")
	}

	return secret, nil
}

// TOTPInfo contains all parameters extracted from an otpauth:// URI.
type TOTPInfo struct {
	Secret    string
	Issuer    string
	Account   string
	Algorithm string // "SHA1", "SHA256", "SHA512"; empty means SHA1
	Digits    int    // 0 means default (6)
	Period    int    // 0 means default (30)
}

// ExtractTOTPFullInfo extracts all TOTP parameters from an otpauth:// URI,
// including algorithm, digits, and period for non-standard configurations.
// Only otpauth://totp/ URIs are accepted; HOTP and other types are
// rejected because sesh does not support counter-based OTP.
func ExtractTOTPFullInfo(otpauthURL string) (TOTPInfo, error) {
	parsedURL, err := parseOTPAuth(otpauthURL)
	if err != nil {
		return TOTPInfo{}, err
	}

	query := parsedURL.Query()
	info := TOTPInfo{
		Secret:    query.Get("secret"),
		Issuer:    query.Get("issuer"),
		Algorithm: strings.ToUpper(query.Get("algorithm")),
	}

	if d := query.Get("digits"); d != "" {
		n, err := strconv.Atoi(d)
		if err != nil || n < 6 || n > 8 {
			return TOTPInfo{}, errors.New("invalid digits value: must be 6, 7, or 8")
		}
		info.Digits = n
	}
	if p := query.Get("period"); p != "" {
		n, err := strconv.Atoi(p)
		// Upper bound mirrors totp.MaxTOTPPeriodSeconds (1 day) — keeps
		// params.Period * time.Second safely inside int64 nanoseconds.
		// Hardcoded here to avoid a circular import from the qrcode package.
		if err != nil || n <= 0 || n > 86400 {
			return TOTPInfo{}, errors.New("invalid period value: must be a positive integer ≤ 86400")
		}
		info.Period = n
	}

	// Extract label. Per the Key URI Format, the label is "issuer:account"
	// and the delimiter is the *first literal* colon — an encoded %3A in
	// the account must not split the label. parsedURL.Path would already
	// have decoded %3A to `:`, so use EscapedPath() to split on the raw
	// form, then URL-decode each half separately.
	label := strings.TrimPrefix(parsedURL.EscapedPath(), "/")
	rawAccount := label
	if before, after, ok := strings.Cut(label, ":"); ok {
		if info.Issuer == "" {
			issuer, unescErr := url.PathUnescape(before)
			if unescErr != nil {
				return TOTPInfo{}, fmt.Errorf("decode issuer in label: %w", unescErr)
			}
			info.Issuer = issuer
		}
		rawAccount = after
	}
	account, err := url.PathUnescape(rawAccount)
	if err != nil {
		return TOTPInfo{}, fmt.Errorf("decode account in label: %w", err)
	}
	// The format allows spaces before the account name.
	info.Account = strings.TrimSpace(account)

	if info.Secret == "" {
		return TOTPInfo{}, fmt.Errorf("no secret found in QR code")
	}

	return info, nil
}

// ReadTexts returns the text of every QR code in img. A code light on
// dark, or in a large photo, is looked for too: the image is also tried
// inverted, and at a half and a quarter of its size.
func ReadTexts(img image.Image) ([]string, error) {
	hints := map[gozxing.DecodeHintType]any{gozxing.DecodeHintType_TRY_HARDER: true}
	var lastErr error
	for _, scaled := range []image.Image{img, shrink(img, 2), shrink(img, 4)} {
		if scaled == nil {
			continue
		}
		// Both ways round at each size, so a picture with a code each way
		// gives both.
		var texts []string
		src := gozxing.NewLuminanceSourceFromImage(scaled)
		for _, s := range []gozxing.LuminanceSource{src, gozxing.NewInvertedLuminanceSource(src)} {
			bmp, err := gozxing.NewBinaryBitmap(gozxing.NewHybridBinarizer(s))
			if err != nil {
				lastErr = err
				continue
			}
			results, err := multiqr.NewQRCodeMultiReader().DecodeMultiple(bmp, hints)
			if err != nil {
				lastErr = err
				continue
			}
			for _, r := range results {
				if t := r.GetText(); !slices.Contains(texts, t) {
					texts = append(texts, t)
				}
			}
		}
		if len(texts) > 0 {
			return texts, nil
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no QR code found")
	}
	return nil, lastErr
}

// shrink returns img in grey at 1/f of its size, each pixel the average of
// the f×f it stands for; nil when that would be too small to hold a code.
func shrink(img image.Image, f int) image.Image {
	b := img.Bounds()
	w, h := b.Dx()/f, b.Dy()/f
	if w < 100 || h < 100 {
		return nil
	}
	out := image.NewGray(image.Rect(0, 0, w, h))
	for y := range h {
		for x := range w {
			sum := 0
			for dy := range f {
				for dx := range f {
					sum += int(color.GrayModel.Convert(img.At(b.Min.X+x*f+dx, b.Min.Y+y*f+dy)).(color.Gray).Y)
				}
			}
			out.SetGray(x, y, color.Gray{Y: uint8(sum / (f * f))}) //nolint:gosec // an average of bytes
		}
	}
	return out
}

// ReadTextsFromFile returns the text of every QR code in the image file at
// path, a PNG or a JPEG, whatever its name says. An iPhone photo (HEIC)
// is refused, saying how to convert it.
func ReadTextsFromFile(path string) ([]string, error) {
	b, err := os.ReadFile(path) //nolint:gosec // the file the user named
	if err != nil {
		return nil, err
	}
	return ReadTextsFromBytes(path, b)
}

// ReadTextsFromBytes is ReadTextsFromFile for an image already read, b,
// called path in errors.
func ReadTextsFromBytes(path string, b []byte) ([]string, error) {
	if IsHEIC(path, b) && path == "stdin" {
		return nil, errors.New("the picture is a HEIC photo, which sesh can't read; convert it to PNG first, for example with: sips -s format png <photo> --out <photo>.png")
	}
	if IsHEIC(path, b) {
		out := strings.TrimSuffix(path, filepath.Ext(path)) + ".png"
		return nil, fmt.Errorf("%s is a HEIC photo, which sesh can't read; convert it to PNG first: sips -s format png %s --out %s", path, shell.Quote(path), shell.Quote(out))
	}
	img, _, err := image.Decode(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("%s isn't a PNG or JPEG image sesh can read: %w", path, err)
	}
	texts, err := ReadTexts(img)
	if err != nil {
		return nil, fmt.Errorf("no QR code found in %s: make sure the whole code is in the picture, sharp and not cut off", path)
	}
	return texts, nil
}

// IsHEIC reports whether a file, at path with content b, is a HEIC photo.
func IsHEIC(path string, b []byte) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".heic" || ext == ".heif" || (len(b) >= 12 && string(b[4:8]) == "ftyp" && strings.HasPrefix(string(b[8:12]), "hei"))
}

// IsImage reports whether b is a PNG, JPEG, or HEIC image, by its first
// bytes.
func IsImage(path string, b []byte) bool {
	return bytes.HasPrefix(b, []byte("\x89PNG\r\n\x1a\n")) || bytes.HasPrefix(b, []byte{0xff, 0xd8, 0xff}) || IsHEIC(path, b)
}

// ReadTOTPFromFile reads the one TOTP QR code in the image file at path, a
// PNG or a JPEG (a screenshot, or a photo of a screen): its otpauth://
// link, and what that says.
func ReadTOTPFromFile(path string) (link string, info TOTPInfo, err error) {
	texts, err := ReadTextsFromFile(path)
	if err != nil {
		return "", TOTPInfo{}, err
	}
	var links []string
	for _, t := range texts {
		switch lower := strings.ToLower(t); {
		case strings.HasPrefix(lower, "otpauth://totp/"):
			links = append(links, t)
		case strings.HasPrefix(lower, "otpauth-migration://"):
			return "", TOTPInfo{}, fmt.Errorf("%s is Google Authenticator's transfer code, which holds several accounts: sesh import --from google-authenticator %s reads it", path, shell.Quote(path))
		}
	}
	switch len(links) {
	case 0:
		return "", TOTPInfo{}, fmt.Errorf("the QR code in %s isn't a TOTP key (an otpauth://totp/ link)", path)
	case 1:
		info, err := ExtractTOTPFullInfo(links[0])
		return links[0], info, err
	}
	return "", TOTPInfo{}, fmt.Errorf("%s has %d TOTP QR codes: crop it to the one to add", path, len(links))
}
