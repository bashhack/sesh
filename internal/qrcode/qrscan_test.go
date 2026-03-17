package qrcode

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
	"github.com/pquerna/otp/totp"
)

func TestExtractTOTPInfo(t *testing.T) {
	tests := map[string]struct {
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
			wantLabel:  "alice@example.com",
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
			wantIssuer: "GitHub",
			wantLabel:  "username",
			wantErr:    false,
		},
		"uri with url-encoded characters": {
			uri:        "otpauth://totp/My%20Service:user%40email.com?secret=JBSWY3DPEHPK3PXP&issuer=My%20Service",
			wantSecret: "JBSWY3DPEHPK3PXP",
			wantIssuer: "My Service",
			wantLabel:  "user@email.com",
			wantErr:    false,
		},
		"invalid scheme": {
			uri:     "http://totp/Example:alice?secret=JBSWY3DPEHPK3PXP",
			wantErr: true,
			errMsg:  "not a valid otpauth URL",
		},
		"wrong auth type": {
			uri:        "otpauth://hotp/Example:alice?secret=JBSWY3DPEHPK3PXP",
			wantErr:    false,
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
		"path with multiple segments": {
			uri:        "otpauth://totp/service.com/department/user?secret=JBSWY3DPEHPK3PXP",
			wantSecret: "JBSWY3DPEHPK3PXP",
			wantIssuer: "",
			wantLabel:  "service.com/department/user",
			wantErr:    false,
		},
		"extremely long secret": {
			uri:        "otpauth://totp/Example:alice?secret=" + strings.Repeat("A", 1000) + "&issuer=Example",
			wantSecret: strings.Repeat("A", 1000),
			wantIssuer: "Example",
			wantLabel:  "alice",
			wantErr:    false,
		},
		"special characters in label": {
			uri:        "otpauth://totp/Test%20%26%20Co.:user%40test.com?secret=JBSWY3DPEHPK3PXP",
			wantSecret: "JBSWY3DPEHPK3PXP",
			wantIssuer: "Test & Co.",
			wantLabel:  "user@test.com",
			wantErr:    false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			secret, issuer, label, err := ExtractTOTPInfo(tc.uri)

			if (err != nil) != tc.wantErr {
				t.Errorf("ExtractTOTPInfo() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			if tc.wantErr && tc.errMsg != "" {
				if !strings.Contains(err.Error(), tc.errMsg) {
					t.Errorf("Expected error containing %q, got %q", tc.errMsg, err.Error())
				}
				return
			}

			if !tc.wantErr {
				if secret != tc.wantSecret {
					t.Errorf("Secret = %v, want %v", secret, tc.wantSecret)
				}
				if issuer != tc.wantIssuer {
					t.Errorf("Issuer = %v, want %v", issuer, tc.wantIssuer)
				}
				if label != tc.wantLabel {
					t.Errorf("Label = %v, want %v", label, tc.wantLabel)
				}
			}
		})
	}
}

func TestExtractSecretFromOTPAuthURL(t *testing.T) {
	tests := map[string]struct {
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

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			secret, err := ExtractSecretFromOTPAuthURL(tc.url)

			if (err != nil) != tc.wantErr {
				t.Errorf("ExtractSecretFromOTPAuthURL() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			if tc.wantErr && tc.errMsg != "" {
				if !strings.Contains(err.Error(), tc.errMsg) {
					t.Errorf("Expected error containing %q, got %q", tc.errMsg, err.Error())
				}
				return
			}

			if !tc.wantErr && secret != tc.wantSecret {
				t.Errorf("Secret = %v, want %v", secret, tc.wantSecret)
			}
		})
	}
}

func TestScanQRCode(t *testing.T) {
	originalExecCommand := execCommand
	originalOSStat := osStat
	defer func() {
		execCommand = originalExecCommand
		osStat = originalOSStat
	}()

	tests := map[string]struct {
		mockExecCmd func(name string, args ...string) *exec.Cmd
		mockStat    func(name string) (os.FileInfo, error)
		wantErr     bool
		errMsg      string
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
					return exec.Command("true")
				}
				return exec.Command("echo")
			},
			mockStat: func(name string) (os.FileInfo, error) {
				return nil, os.ErrNotExist
			},
			wantErr: true,
			errMsg:  "screenshot capture was canceled or failed",
		},
		"file too small": {
			mockExecCmd: func(name string, args ...string) *exec.Cmd {
				if name == "screencapture" {
					return exec.Command("true")
				}
				return exec.Command("echo")
			},
			mockStat: func(name string) (os.FileInfo, error) {
				return mockFileInfo{size: 50}, nil
			},
			wantErr: true,
			errMsg:  "screenshot capture was canceled or failed",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			execCommand = tc.mockExecCmd
			if tc.mockStat != nil {
				osStat = tc.mockStat
			}

			_, err := ScanQRCode()

			if (err != nil) != tc.wantErr {
				t.Errorf("ScanQRCode() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			if tc.wantErr && tc.errMsg != "" && !strings.Contains(err.Error(), tc.errMsg) {
				t.Errorf("Expected error containing %q, got %q", tc.errMsg, err.Error())
			}
		})
	}
}

type mockFileInfo struct {
	size int64
}

func (m mockFileInfo) Name() string       { return "test.png" }
func (m mockFileInfo) Size() int64        { return m.size }
func (m mockFileInfo) Mode() os.FileMode  { return 0644 }
func (m mockFileInfo) ModTime() time.Time { return time.Now() }
func (m mockFileInfo) IsDir() bool        { return false }
func (m mockFileInfo) Sys() any           { return nil }

func TestDecodeQRCodeFromFile(t *testing.T) {
	tests := map[string]struct {
		setup   func() string
		cleanup func(string)
		wantErr bool
		errMsg  string
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
				f, err := os.CreateTemp("", "invalid*.png")
				if err != nil {
					panic("test setup: failed to create temp file: " + err.Error())
				}
				if _, err := f.WriteString("not a png file"); err != nil {
					panic("test setup: failed to write temp file: " + err.Error())
				}
				if err := f.Close(); err != nil {
					panic("test setup: failed to close temp file: " + err.Error())
				}
				return f.Name()
			},
			cleanup: func(name string) {
				if err := os.Remove(name); err != nil {
					// Best effort in cleanup — file may already be gone
					return
				}
			},
			wantErr: true,
			errMsg:  "failed to decode image",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			filename := tc.setup()
			defer tc.cleanup(filename)

			_, err := DecodeQRCodeFromFile(filename)

			if (err != nil) != tc.wantErr {
				t.Errorf("DecodeQRCodeFromFile() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			if tc.wantErr && tc.errMsg != "" && !strings.Contains(err.Error(), tc.errMsg) {
				t.Errorf("Expected error containing %q, got %q", tc.errMsg, err.Error())
			}
		})
	}
}

func TestDecodeQRCodeFromImage_Errors(t *testing.T) {
	tests := map[string]struct {
		image image.Image
	}{
		"empty dimensions": {
			image: image.NewGray(image.Rect(0, 0, 0, 0)),
		},
		"checkerboard pattern": {
			image: createCheckerboardImage(100, 100),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := DecodeQRCodeFromImage(tc.image)
			if err == nil {
				t.Error("Expected error for invalid image")
			}
		})
	}
}

func createCheckerboardImage(width, height int) image.Image {
	img := image.NewGray(image.Rect(0, 0, width, height))
	for x := range width {
		for y := range height {
			if (x/10+y/10)%2 == 0 {
				img.Set(x, y, color.White)
			} else {
				img.Set(x, y, color.Black)
			}
		}
	}
	return img
}

func TestGenerateValidQRCode(t *testing.T) {
	tests := map[string]struct {
		accountName string
		issuer      string
		secret      string
	}{
		"basic TOTP": {
			accountName: "alice@example.com",
			issuer:      "TestApp",
			secret:      "JBSWY3DPEHPK3PXP",
		},
		"with special characters": {
			accountName: "user+test@example.com",
			issuer:      "Test & Co.",
			secret:      "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			key, err := totp.Generate(totp.GenerateOpts{
				Issuer:      tc.issuer,
				AccountName: tc.accountName,
				Secret:      []byte(tc.secret),
			})
			if err != nil {
				t.Fatalf("Failed to generate TOTP key: %v", err)
			}

			var buf bytes.Buffer
			img, err := key.Image(200, 200)
			if err != nil {
				t.Fatalf("Failed to generate QR image: %v", err)
			}

			if err := png.Encode(&buf, img); err != nil {
				t.Fatalf("Failed to encode PNG: %v", err)
			}

			decodedImg, err := png.Decode(&buf)
			if err != nil {
				t.Fatalf("Failed to decode PNG: %v", err)
			}

			secret, err := DecodeQRCodeFromImage(decodedImg)
			if err != nil {
				t.Fatalf("Failed to decode QR code: %v", err)
			}

			if secret == "" {
				t.Error("Expected non-empty secret from QR code")
			}
		})
	}
}

func TestDecodeNonTOTPQRCode(t *testing.T) {
	tests := map[string]struct {
		data    string
		wantErr string
	}{
		"plain URL": {
			data:    "https://example.com",
			wantErr: "not a valid otpauth URL",
		},
		"plain text": {
			data:    "Hello, World!",
			wantErr: "not a valid otpauth URL",
		},
		"email": {
			data:    "mailto:test@example.com",
			wantErr: "not a valid otpauth URL",
		},
		"WiFi credentials": {
			data:    "WIFI:T:WPA;S:MyNetwork;P:MyPassword;;",
			wantErr: "not a valid otpauth URL",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			qrWriter := qrcode.NewQRCodeWriter()
			bitMatrix, err := qrWriter.Encode(tc.data, gozxing.BarcodeFormat_QR_CODE, 200, 200, nil)
			if err != nil {
				t.Fatalf("Failed to encode QR code: %v", err)
			}

			img := image.NewGray(image.Rect(0, 0, 200, 200))
			for y := range 200 {
				for x := range 200 {
					if bitMatrix.Get(x, y) {
						img.Set(x, y, color.Black)
					} else {
						img.Set(x, y, color.White)
					}
				}
			}

			_, err = DecodeQRCodeFromImage(img)
			if err == nil {
				t.Error("Expected error for non-TOTP QR code")
			}

			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Expected error containing %q, got %q", tc.wantErr, err.Error())
			}
		})
	}
}

func TestScanQRCodePlatform(t *testing.T) {
	originalExecCommand := execCommand
	originalOSStat := osStat
	defer func() {
		execCommand = originalExecCommand
		osStat = originalOSStat
	}()

	if runtime.GOOS != "darwin" {
		execCommand = func(name string, args ...string) *exec.Cmd {
			if name == "screencapture" {
				return exec.Command("false")
			}
			return exec.Command("echo")
		}

		_, err := ScanQRCode()
		if err == nil {
			t.Error("Expected error on non-macOS platform")
		}
	}
}

func TestScanQRCodeCleanup(t *testing.T) {
	originalExecCommand := execCommand
	originalOSStat := osStat
	defer func() {
		execCommand = originalExecCommand
		osStat = originalOSStat
	}()

	tempFiles := make([]string, 0)

	execCommand = func(name string, args ...string) *exec.Cmd {
		if name == "screencapture" && len(args) >= 2 {
			tempFiles = append(tempFiles, args[1])
			return exec.Command("false")
		}
		return exec.Command("echo")
	}

	_, err := ScanQRCode()
	if err == nil {
		t.Error("Expected error from failed screencapture")
	}

	time.Sleep(100 * time.Millisecond)
	for _, file := range tempFiles {
		if _, err := os.Stat(file); err == nil {
			t.Errorf("Temp file %s was not cleaned up", file)
			if err := os.Remove(file); err != nil {
				t.Errorf("failed to remove leftover temp file: %v", err)
			}
		}
	}
}

func TestConcurrentQRDecoding(t *testing.T) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "TestApp",
		AccountName: "test@example.com",
	})
	if err != nil {
		t.Fatalf("Failed to generate TOTP key: %v", err)
	}

	rawImg, err := key.Image(200, 200)
	if err != nil {
		t.Fatalf("Failed to generate QR image: %v", err)
	}

	// Encode/decode through PNG so each goroutine works with a concrete
	// *image.NRGBA that is safe for concurrent reads. The raw
	// *barcode.scaledBarcode may not be goroutine-safe.
	var buf bytes.Buffer
	if err := png.Encode(&buf, rawImg); err != nil {
		t.Fatalf("Failed to encode PNG: %v", err)
	}
	img, err := png.Decode(&buf)
	if err != nil {
		t.Fatalf("Failed to decode PNG: %v", err)
	}

	const goroutines = 100
	var wg sync.WaitGroup
	errors := make(chan error, goroutines)

	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := DecodeQRCodeFromImage(img)
			if err != nil {
				errors <- err
			}
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("Concurrent decode error: %v", err)
	}
}

func TestDecodeQRCodeFromFile_Integration(t *testing.T) {
	if os.Getenv("CI") != "" {
		t.Skip("skipping integration test in CI (no display)")
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Integration Test",
		AccountName: "integration@test.com",
	})
	if err != nil {
		t.Fatalf("Failed to generate TOTP key: %v", err)
	}

	img, err := key.Image(300, 300)
	if err != nil {
		t.Fatalf("Failed to generate QR image: %v", err)
	}

	tmpFile, err := os.CreateTemp("", "qr_test_*.png")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() {
		if err := os.Remove(tmpFile.Name()); err != nil {
			t.Errorf("failed to remove temp file: %v", err)
		}
	}()

	if err := png.Encode(tmpFile, img); err != nil {
		t.Fatalf("Failed to encode PNG: %v", err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatalf("Failed to close temp file: %v", err)
	}

	secret, err := DecodeQRCodeFromFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to decode QR from file: %v", err)
	}

	if secret == "" {
		t.Error("Expected non-empty secret")
	}

	_, err = DecodeQRCodeFromFile("/nonexistent/qr.png")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
}
