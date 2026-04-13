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
	"strings"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
)

var (
	execCommand = exec.Command
	osStat      = os.Stat
)

// ScanQRCode captures a QR code using screenshots and extracts the TOTP secret
func ScanQRCode() (string, error) {
	tmp, err := os.CreateTemp("", "sesh-qr-*.png")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	tempFile := tmp.Name()
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("close temp file: %w", err)
	}
	defer func() {
		if err := os.Remove(tempFile); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "warning: failed to remove temp file %s: %v\n", tempFile, err)
		}
	}()

	fmt.Println("📸 Please select the area containing the QR code...")
	cmd := execCommand("screencapture", "-i", tempFile)
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("failed to capture screenshot: %w", err)
	}

	// Check if the user canceled (file would be empty or very small)
	fileInfo, err := osStat(tempFile)
	if err != nil || fileInfo.Size() < 100 {
		return "", fmt.Errorf("screenshot capture was canceled or failed")
	}

	fmt.Println("✅ Screenshot captured, processing QR code...")

	return DecodeQRCodeFromFile(tempFile)
}

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

// ExtractSecretFromOTPAuthURL extracts just the secret from an otpauth URL
func ExtractSecretFromOTPAuthURL(otpauthURL string) (string, error) {
	if !strings.HasPrefix(otpauthURL, "otpauth://") {
		return "", fmt.Errorf("not a valid otpauth URL: %s", otpauthURL)
	}

	parsedURL, err := url.Parse(otpauthURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse otpauth URL: %w", err)
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

// ExtractTOTPInfo extracts additional information from a TOTP QR code
// Returns secret, issuer, account name
func ExtractTOTPInfo(otpauthURL string) (string, string, string, error) {
	info, err := ExtractTOTPFullInfo(otpauthURL)
	if err != nil {
		return "", "", "", err
	}
	return info.Secret, info.Issuer, info.Account, nil
}

// ExtractTOTPFullInfo extracts all TOTP parameters from an otpauth:// URI,
// including algorithm, digits, and period for non-standard configurations.
func ExtractTOTPFullInfo(otpauthURL string) (TOTPInfo, error) {
	if !strings.HasPrefix(otpauthURL, "otpauth://") {
		return TOTPInfo{}, fmt.Errorf("not a valid otpauth URL: %s", otpauthURL)
	}

	parsedURL, err := url.Parse(otpauthURL)
	if err != nil {
		return TOTPInfo{}, fmt.Errorf("failed to parse otpauth URL: %w", err)
	}

	query := parsedURL.Query()
	info := TOTPInfo{
		Secret:    query.Get("secret"),
		Issuer:    query.Get("issuer"),
		Algorithm: strings.ToUpper(query.Get("algorithm")),
	}

	if d := query.Get("digits"); d != "" {
		if _, err := fmt.Sscanf(d, "%d", &info.Digits); err != nil {
			return TOTPInfo{}, fmt.Errorf("invalid digits value %q: %w", d, err)
		}
	}
	if p := query.Get("period"); p != "" {
		if _, err := fmt.Sscanf(p, "%d", &info.Period); err != nil {
			return TOTPInfo{}, fmt.Errorf("invalid period value %q: %w", p, err)
		}
	}

	// Extract label (which might contain issuer and account)
	label := strings.TrimPrefix(parsedURL.Path, "/")
	info.Account = label
	if i := strings.LastIndex(label, ":"); i >= 0 {
		if info.Issuer == "" {
			info.Issuer = label[:i]
		}
		info.Account = label[i+1:]
	}

	if info.Secret == "" {
		return TOTPInfo{}, fmt.Errorf("no secret found in QR code")
	}

	return info, nil
}
