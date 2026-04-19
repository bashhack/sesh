// Package qrcode provides QR code scanning and decoding from screen captures.
package qrcode

import (
	"fmt"
	"image"
	"image/png"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/makiuchi-d/gozxing"
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
	tmp, err := os.CreateTemp("", "sesh-qr-*.png")
	if err != nil {
		return TOTPInfo{}, fmt.Errorf("failed to create temp file: %w", err)
	}
	tempFile := tmp.Name()
	if err := tmp.Close(); err != nil {
		return TOTPInfo{}, fmt.Errorf("close temp file: %w", err)
	}
	defer func() {
		if err := os.Remove(tempFile); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "warning: failed to remove temp file %s: %v\n", tempFile, err)
		}
	}()

	fmt.Println("📸 Please select the area containing the QR code...")
	cmd := execCommand("screencapture", "-i", tempFile)
	if err := cmd.Run(); err != nil {
		return TOTPInfo{}, fmt.Errorf("failed to capture screenshot: %w", err)
	}

	fileInfo, err := osStat(tempFile)
	if err != nil || fileInfo.Size() < 100 {
		return TOTPInfo{}, fmt.Errorf("screenshot capture was canceled or failed")
	}

	fmt.Println("✅ Screenshot captured, processing QR code...")

	file, err := os.Open(filepath.Clean(tempFile))
	if err != nil {
		return TOTPInfo{}, fmt.Errorf("failed to open screenshot: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to close screenshot file: %v\n", err)
		}
	}()

	img, err := png.Decode(file)
	if err != nil {
		return TOTPInfo{}, fmt.Errorf("failed to decode screenshot: %w", err)
	}

	return DecodeQRCodeFromImageFull(img)
}

// ExtractSecretFromOTPAuthURL extracts just the secret from an otpauth
// URL. Only otpauth://totp/ URIs are accepted.
func ExtractSecretFromOTPAuthURL(otpauthURL string) (string, error) {
	if !strings.HasPrefix(otpauthURL, "otpauth://") {
		return "", fmt.Errorf("not a valid otpauth URL: %s", otpauthURL)
	}

	parsedURL, err := url.Parse(otpauthURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse otpauth URL: %w", err)
	}
	if parsedURL.Host != "totp" {
		return "", fmt.Errorf("unsupported OTP type %q (only TOTP is supported)", parsedURL.Host)
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
	if !strings.HasPrefix(otpauthURL, "otpauth://") {
		return TOTPInfo{}, fmt.Errorf("not a valid otpauth URL: %s", otpauthURL)
	}

	parsedURL, err := url.Parse(otpauthURL)
	if err != nil {
		return TOTPInfo{}, fmt.Errorf("failed to parse otpauth URL: %w", err)
	}
	if parsedURL.Host != "totp" {
		return TOTPInfo{}, fmt.Errorf("unsupported OTP type %q (only TOTP is supported)", parsedURL.Host)
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
			return TOTPInfo{}, fmt.Errorf("invalid digits value %q: must be 6, 7, or 8", d)
		}
		info.Digits = n
	}
	if p := query.Get("period"); p != "" {
		n, err := strconv.Atoi(p)
		// Upper bound mirrors totp.MaxTOTPPeriodSeconds (1 day) — keeps
		// params.Period * time.Second safely inside int64 nanoseconds.
		// Hardcoded here to avoid a circular import from the qrcode package.
		if err != nil || n <= 0 || n > 86400 {
			return TOTPInfo{}, fmt.Errorf("invalid period value %q: must be a positive integer ≤ 86400", p)
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
	info.Account = account

	if info.Secret == "" {
		return TOTPInfo{}, fmt.Errorf("no secret found in QR code")
	}

	return info, nil
}
