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

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			execCommand = tt.mockExecCmd
			if tt.mockStat != nil {
				osStat = tt.mockStat
			}

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

type mockFileInfo struct {
	size int64
}

func (m mockFileInfo) Name() string       { return "test.png" }
func (m mockFileInfo) Size() int64        { return m.size }
func (m mockFileInfo) Mode() os.FileMode  { return 0644 }
func (m mockFileInfo) ModTime() time.Time { return time.Now() }
func (m mockFileInfo) IsDir() bool        { return false }
func (m mockFileInfo) Sys() interface{}   { return nil }

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

func TestDecodeQRCodeFromImage_Errors(t *testing.T) {
	tests := map[string]struct {
		name  string
		image image.Image
	}{
		"empty image": {
			name:  "empty dimensions",
			image: image.NewGray(image.Rect(0, 0, 0, 0)),
		},
		"invalid qr pattern": {
			name:  "checkerboard pattern",
			image: createCheckerboardImage(100, 100),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeQRCodeFromImage(tt.image)
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

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			key, err := totp.Generate(totp.GenerateOpts{
				Issuer:      tt.issuer,
				AccountName: tt.accountName,
				Secret:      []byte(tt.secret),
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

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			qrWriter := qrcode.NewQRCodeWriter()
			bitMatrix, err := qrWriter.Encode(tt.data, gozxing.BarcodeFormat_QR_CODE, 200, 200, nil)
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

			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Expected error containing %q, got %q", tt.wantErr, err.Error())
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
			os.Remove(file)
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

	img, err := key.Image(200, 200)
	if err != nil {
		t.Fatalf("Failed to generate QR image: %v", err)
	}

	var wg sync.WaitGroup
	errors := make(chan error, 10)

	for range 10 {
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
	defer os.Remove(tmpFile.Name())

	if err := png.Encode(tmpFile, img); err != nil {
		t.Fatalf("Failed to encode PNG: %v", err)
	}
	tmpFile.Close()

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
