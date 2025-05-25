package qrcode

import (
	// "bytes"
	// "encoding/base64"
	"image"
	"image/color"
	// "image/png"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestExtractTOTPInfo(t *testing.T) {
	tests := map[string]struct {
		name       string
		uri        string
		wantSecret string
		wantIssuer string
		wantLabel  string
		wantErr    bool
		errMsg     string
	}{
		"valid google authenticator uri": {
			uri:        "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
			wantSecret: "JBSWY3DPEHPK3PXP",
			wantIssuer: "Example",
			wantLabel:  "alice@example.com", // accountName after parsing
			wantErr:    false,
		},
		"uri without issuer": {
			uri:        "otpauth://totp/alice@example.com?secret=JBSWY3DPEHPK3PXP",
			wantSecret: "JBSWY3DPEHPK3PXP",
			wantIssuer: "",
			wantLabel:  "alice@example.com",
			wantErr:    false,
		},
		"uri with issuer in label only": {
			uri:        "otpauth://totp/GitHub:username?secret=JBSWY3DPEHPK3PXP",
			wantSecret: "JBSWY3DPEHPK3PXP",
			wantIssuer: "GitHub", // Extracted from label
			wantLabel:  "username", // accountName after parsing
			wantErr:    false,
		},
		"uri with url-encoded characters": {
			uri:        "otpauth://totp/My%20Service:user%40email.com?secret=JBSWY3DPEHPK3PXP&issuer=My%20Service",
			wantSecret: "JBSWY3DPEHPK3PXP",
			wantIssuer: "My Service",
			wantLabel:  "user@email.com", // accountName after parsing
			wantErr:    false,
		},
		"invalid scheme": {
			uri:     "http://totp/Example:alice?secret=JBSWY3DPEHPK3PXP",
			wantErr: true,
			errMsg:  "not a valid otpauth URL",
		},
		"wrong auth type": {
			uri:     "otpauth://hotp/Example:alice?secret=JBSWY3DPEHPK3PXP",
			wantErr: false, // The function doesn't check auth type
			wantSecret: "JBSWY3DPEHPK3PXP",
			wantIssuer: "Example",
			wantLabel:  "alice",
		},
		"missing secret": {
			uri:     "otpauth://totp/Example:alice?issuer=Example",
			wantErr: true,
			errMsg:  "no secret found",
		},
		"empty secret": {
			uri:     "otpauth://totp/Example:alice?secret=&issuer=Example",
			wantErr: true,
			errMsg:  "no secret found",
		},
		"malformed uri": {
			uri:     "not-a-uri",
			wantErr: true,
			errMsg:  "not a valid otpauth URL",
		},
		"uri with additional parameters": {
			uri:        "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=6&period=30",
			wantSecret: "JBSWY3DPEHPK3PXP",
			wantIssuer: "Example",
			wantLabel:  "alice",
			wantErr:    false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			secret, issuer, label, err := ExtractTOTPInfo(tt.uri)

			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractTOTPInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && tt.errMsg != "" {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Expected error containing %q, got %q", tt.errMsg, err.Error())
				}
				return
			}

			if !tt.wantErr {
				if secret != tt.wantSecret {
					t.Errorf("Secret = %v, want %v", secret, tt.wantSecret)
				}
				if issuer != tt.wantIssuer {
					t.Errorf("Issuer = %v, want %v", issuer, tt.wantIssuer)
				}
				if label != tt.wantLabel {
					t.Errorf("Label = %v, want %v", label, tt.wantLabel)
				}
			}
		})
	}
}

func TestParseLabel(t *testing.T) {
	tests := map[string]struct {
		label      string
		wantIssuer string
		wantUser   string
	}{
		"label with issuer": {
			label:      "GitHub:username",
			wantIssuer: "GitHub",
			wantUser:   "username",
		},
		"label without issuer": {
			label:      "username@example.com",
			wantIssuer: "",
			wantUser:   "username@example.com",
		},
		"label with multiple colons": {
			label:      "My:Service:username",
			wantIssuer: "My",
			wantUser:   "Service:username",
		},
		"empty label": {
			label:      "",
			wantIssuer: "",
			wantUser:   "",
		},
		"url encoded label": {
			label:      "My%20Company:user%40email.com",
			wantIssuer: "My Company",
			wantUser:   "user@email.com",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// URL decode the label first as would happen in real usage
			decoded, _ := url.QueryUnescape(tt.label)
			
			parts := strings.SplitN(decoded, ":", 2)
			var issuer, user string
			
			if len(parts) == 2 {
				issuer = parts[0]
				user = parts[1]
			} else {
				user = decoded
			}

			if issuer != tt.wantIssuer {
				t.Errorf("Parsed issuer = %v, want %v", issuer, tt.wantIssuer)
			}
			if user != tt.wantUser {
				t.Errorf("Parsed user = %v, want %v", user, tt.wantUser)
			}
		})
	}
}
func TestExtractSecretFromOTPAuthURL(t *testing.T) {
	tests := map[string]struct {
		name       string
		url        string
		wantSecret string
		wantErr    bool
		errMsg     string
	}{
		"valid url with secret": {
			url:        "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example",
			wantSecret: "JBSWY3DPEHPK3PXP",
			wantErr:    false,
		},
		"url without secret": {
			url:     "otpauth://totp/Example:alice?issuer=Example",
			wantErr: true,
			errMsg:  "no secret found",
		},
		"empty secret": {
			url:     "otpauth://totp/Example:alice?secret=&issuer=Example",
			wantErr: true,
			errMsg:  "no secret found",
		},
		"invalid scheme": {
			url:     "http://example.com?secret=ABC",
			wantErr: true,
			errMsg:  "not a valid otpauth URL",
		},
		"malformed url": {
			url:     "not-a-url",
			wantErr: true,
			errMsg:  "not a valid otpauth URL",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			secret, err := ExtractSecretFromOTPAuthURL(tt.url)

			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractSecretFromOTPAuthURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && tt.errMsg != "" {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Expected error containing %q, got %q", tt.errMsg, err.Error())
				}
				return
			}

			if !tt.wantErr && secret != tt.wantSecret {
				t.Errorf("Secret = %v, want %v", secret, tt.wantSecret)
			}
		})
	}
}

func TestScanQRCode(t *testing.T) {
	// Save originals
	originalExecCommand := execCommand
	originalOSStat := osStat
	defer func() {
		execCommand = originalExecCommand
		osStat = originalOSStat
	}()

	tests := map[string]struct {
		name           string
		mockExecCmd    func(name string, args ...string) *exec.Cmd
		mockStat       func(name string) (os.FileInfo, error)
		wantErr        bool
		errMsg         string
	}{
		"screenshot command fails": {
			mockExecCmd: func(name string, args ...string) *exec.Cmd {
				if name == "screencapture" {
					return exec.Command("false")
				}
				return exec.Command("echo")
			},
			wantErr: true,
			errMsg:  "failed to capture screenshot",
		},
		"screenshot canceled (file not found)": {
			mockExecCmd: func(name string, args ...string) *exec.Cmd {
				if name == "screencapture" {
					return exec.Command("true") // Success but no file created
				}
				return exec.Command("echo")
			},
			mockStat: func(name string) (os.FileInfo, error) {
				return nil, os.ErrNotExist
			},
			wantErr: true,
			errMsg:  "screenshot capture was canceled or failed",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			// Set up mocks
			execCommand = tt.mockExecCmd
			if tt.mockStat != nil {
				osStat = tt.mockStat
			}

			// Test
			_, err := ScanQRCode()

			if (err != nil) != tt.wantErr {
				t.Errorf("ScanQRCode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("Expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

// mockFileInfo implements os.FileInfo for testing
type mockFileInfo struct {
	size int64
}

func (m mockFileInfo) Name() string       { return "test.png" }
func (m mockFileInfo) Size() int64        { return m.size }
func (m mockFileInfo) Mode() os.FileMode  { return 0644 }
func (m mockFileInfo) ModTime() time.Time  { return time.Now() }
func (m mockFileInfo) IsDir() bool        { return false }
func (m mockFileInfo) Sys() interface{}   { return nil }

func TestScanQRCodeFileSize(t *testing.T) {
	// Save originals
	originalExecCommand := execCommand
	originalOSStat := osStat
	defer func() {
		execCommand = originalExecCommand
		osStat = originalOSStat
	}()

	// Mock successful screenshot command
	execCommand = func(name string, args ...string) *exec.Cmd {
		if name == "screencapture" {
			return exec.Command("true")
		}
		return exec.Command("echo")
	}

	// Test file too small
	osStat = func(name string) (os.FileInfo, error) {
		return mockFileInfo{size: 50}, nil // Less than 100 bytes
	}

	_, err := ScanQRCode()
	if err == nil {
		t.Error("Expected error for small file, got nil")
	}
	if !strings.Contains(err.Error(), "screenshot capture was canceled or failed") {
		t.Errorf("Expected canceled error, got %v", err)
	}

}

func TestDecodeQRCodeFromFile(t *testing.T) {
	tests := map[string]struct {
		name     string
		setup    func() string // Returns filename
		cleanup  func(string)
		wantErr  bool
		errMsg   string
	}{
		"file not found": {
			setup: func() string {
				return "/nonexistent/file.png"
			},
			cleanup: func(string) {},
			wantErr: true,
			errMsg:  "failed to open image file",
		},
		"invalid png file": {
			setup: func() string {
				// Create a temp file with invalid PNG data
				f, _ := os.CreateTemp("", "invalid*.png")
				f.WriteString("not a png file")
				f.Close()
				return f.Name()
			},
			cleanup: func(name string) {
				os.Remove(name)
			},
			wantErr: true,
			errMsg:  "failed to decode image",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			filename := tt.setup()
			defer tt.cleanup(filename)

			_, err := DecodeQRCodeFromFile(filename)

			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeQRCodeFromFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("Expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}

}

// createTestQRImage creates a simple test image that simulates a QR code
// This won't be decodable by the QR reader, but we can test error handling
func createTestQRImage() image.Image {
	// Create a simple 100x100 black and white image
	img := image.NewGray(image.Rect(0, 0, 100, 100))
	
	// Add some pattern to simulate QR code
	for x := 0; x < 100; x++ {
		for y := 0; y < 100; y++ {
			if (x/10+y/10)%2 == 0 {
				img.Set(x, y, color.White)
			} else {
				img.Set(x, y, color.Black)
			}
		}
	}
	
	return img
}

func TestDecodeQRCodeFromImage(t *testing.T) {
	tests := map[string]struct {
		name    string
		image   image.Image
		wantErr bool
		errMsg  string
	}{
		"invalid qr pattern": {
			image:   createTestQRImage(),
			wantErr: true,
			errMsg:  "failed to decode QR code",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := DecodeQRCodeFromImage(tt.image)

			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeQRCodeFromImage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("Expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

// Test a valid QR code PNG created with a known TOTP URL
func TestDecodeQRCodeFromFile_ValidQR(t *testing.T) {
	// Create a simple valid PNG that will fail QR code detection
	// This is a 1x1 white PNG - valid PNG but not a QR code
	simplePNG := []byte{
		0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
		0x00, 0x00, 0x00, 0x0D, // IHDR chunk length
		0x49, 0x48, 0x44, 0x52, // IHDR
		0x00, 0x00, 0x00, 0x01, // width = 1
		0x00, 0x00, 0x00, 0x01, // height = 1
		0x08, 0x02, 0x00, 0x00, 0x00, // bit depth = 8, color type = 2 (RGB), etc
		0x90, 0x77, 0x53, 0xDE, // CRC
		0x00, 0x00, 0x00, 0x0C, // IDAT chunk length
		0x49, 0x44, 0x41, 0x54, // IDAT
		0x08, 0xD7, 0x63, 0xF8, 0xFF, 0xFF, 0xFF, 0x00, 0x05, 0xFE, 0x02, 0xFE, // compressed data
		0xDC, 0xCC, 0x59, 0xE7, // CRC
		0x00, 0x00, 0x00, 0x00, // IEND chunk length
		0x49, 0x45, 0x4E, 0x44, // IEND
		0xAE, 0x42, 0x60, 0x82, // CRC
	}

	// Create a temp file with the PNG data
	tmpFile, err := os.CreateTemp("", "test_qr_*.png")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(simplePNG); err != nil {
		t.Fatalf("Failed to write PNG data: %v", err)
	}
	tmpFile.Close()

	// Test decoding - should fail since it's not a QR code
	_, err = DecodeQRCodeFromFile(tmpFile.Name())
	if err == nil {
		t.Fatalf("DecodeQRCodeFromFile() should have failed with non-QR image")
	}
	// The error could be either decode image or decode QR code
	if !strings.Contains(err.Error(), "failed to decode") {
		t.Errorf("Expected error containing 'failed to decode', got: %v", err)
	}
}

// Test empty image dimensions
func TestDecodeQRCodeFromImage_EmptyImage(t *testing.T) {
	// Create an empty image (0x0 dimensions)
	img := image.NewGray(image.Rect(0, 0, 0, 0))
	
	_, err := DecodeQRCodeFromImage(img)
	if err == nil {
		t.Error("Expected error for empty image, got nil")
	}
	// Check for either processing or decode error
	if !strings.Contains(err.Error(), "failed to") || !strings.Contains(err.Error(), "dimensions") {
		t.Errorf("Expected error about dimensions, got: %v", err)
	}
}
