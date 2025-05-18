package qrcode

import (
	"fmt"
	"image/png"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
)

// ScanQRCode captures a QR code using screenshots and extracts the TOTP secret
func ScanQRCode() (string, error) {
	// Create a temp file for the screenshot
	tempFile := filepath.Join(os.TempDir(), fmt.Sprintf("sesh-qr-%d.png", time.Now().UnixNano()))
	defer os.Remove(tempFile) // Clean up when done

	// Use screencapture on macOS
	fmt.Println("📸 Please select the area containing the QR code...")
	cmd := exec.Command("screencapture", "-i", tempFile)
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("failed to capture screenshot: %w", err)
	}

	// Check if the user canceled (file would be empty or very small)
	fileInfo, err := os.Stat(tempFile)
	if err != nil || fileInfo.Size() < 100 {
		return "", fmt.Errorf("screenshot capture was canceled or failed")
	}

	fmt.Println("✅ Screenshot captured, processing QR code...")

	// Open and decode the image
	file, err := os.Open(tempFile)
	if err != nil {
		return "", fmt.Errorf("failed to open screenshot: %w", err)
	}
	defer file.Close()

	img, err := png.Decode(file)
	if err != nil {
		return "", fmt.Errorf("failed to decode image: %w", err)
	}

	// Convert to the format required by gozxing
	bmp, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		return "", fmt.Errorf("failed to process image for QR reading: %w", err)
	}

	// Set up QR code reader
	reader := qrcode.NewQRCodeReader()
	result, err := reader.Decode(bmp, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decode QR code: %w\nMake sure the QR code is clearly visible in the screenshot", err)
	}

	// Extract secret from otpauth URI
	otpauthURL := result.GetText()
	if !strings.HasPrefix(otpauthURL, "otpauth://") {
		return "", fmt.Errorf("not a valid otpauth URL: %s", otpauthURL)
	}

	// Parse the otpauth URL to extract the secret
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

// ExtractTOTPInfo extracts additional information from a TOTP QR code
// Returns secret, issuer, account name
func ExtractTOTPInfo(otpauthURL string) (string, string, string, error) {
	if !strings.HasPrefix(otpauthURL, "otpauth://") {
		return "", "", "", fmt.Errorf("not a valid otpauth URL: %s", otpauthURL)
	}

	// Parse the otpauth URL
	parsedURL, err := url.Parse(otpauthURL)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to parse otpauth URL: %w", err)
	}

	// Extract query parameters
	query := parsedURL.Query()
	secret := query.Get("secret")
	issuer := query.Get("issuer")

	// Extract label (which might contain issuer and account)
	label := parsedURL.Path
	if strings.HasPrefix(label, "/") {
		label = label[1:]
	}

	// If the label contains a colon, it might be in format "issuer:account"
	accountName := label
	if i := strings.LastIndex(label, ":"); i >= 0 {
		if issuer == "" {
			issuer = label[:i]
		}
		accountName = label[i+1:]
	}

	if secret == "" {
		return "", "", "", fmt.Errorf("no secret found in QR code")
	}

	return secret, issuer, accountName, nil
}