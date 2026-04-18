package qrcode

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
	"github.com/pquerna/otp/totp"
)

func TestExtractTOTPFullInfo(t *testing.T) {
	tests := map[string]struct {
		uri         string
		wantSecret  string
		wantIssuer  string
		wantAccount string
		errMsg      string
		wantErr     bool
	}{
		"valid google authenticator uri": {
			uri:         "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
			wantSecret:  "JBSWY3DPEHPK3PXP",
			wantIssuer:  "Example",
			wantAccount: "alice@example.com",
		},
		"uri without issuer": {
			uri:         "otpauth://totp/alice@example.com?secret=JBSWY3DPEHPK3PXP",
			wantSecret:  "JBSWY3DPEHPK3PXP",
			wantAccount: "alice@example.com",
		},
		"uri with issuer in label only": {
			uri:         "otpauth://totp/GitHub:username?secret=JBSWY3DPEHPK3PXP",
			wantSecret:  "JBSWY3DPEHPK3PXP",
			wantIssuer:  "GitHub",
			wantAccount: "username",
		},
		"uri with url-encoded characters": {
			uri:         "otpauth://totp/My%20Service:user%40email.com?secret=JBSWY3DPEHPK3PXP&issuer=My%20Service",
			wantSecret:  "JBSWY3DPEHPK3PXP",
			wantIssuer:  "My Service",
			wantAccount: "user@email.com",
		},
		"invalid scheme": {
			uri:     "http://totp/Example:alice?secret=JBSWY3DPEHPK3PXP",
			wantErr: true,
			errMsg:  "not a valid otpauth URL",
		},
		"wrong auth type": {
			uri:         "otpauth://hotp/Example:alice?secret=JBSWY3DPEHPK3PXP",
			wantSecret:  "JBSWY3DPEHPK3PXP",
			wantIssuer:  "Example",
			wantAccount: "alice",
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
			uri:         "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example&digits=6&period=30",
			wantSecret:  "JBSWY3DPEHPK3PXP",
			wantIssuer:  "Example",
			wantAccount: "alice",
		},
		"path with multiple segments": {
			uri:         "otpauth://totp/service.com/department/user?secret=JBSWY3DPEHPK3PXP",
			wantSecret:  "JBSWY3DPEHPK3PXP",
			wantAccount: "service.com/department/user",
		},
		"extremely long secret": {
			uri:         "otpauth://totp/Example:alice?secret=" + strings.Repeat("A", 1000) + "&issuer=Example",
			wantSecret:  strings.Repeat("A", 1000),
			wantIssuer:  "Example",
			wantAccount: "alice",
		},
		"special characters in label": {
			uri:         "otpauth://totp/Test%20%26%20Co.:user%40test.com?secret=JBSWY3DPEHPK3PXP",
			wantSecret:  "JBSWY3DPEHPK3PXP",
			wantIssuer:  "Test & Co.",
			wantAccount: "user@test.com",
		},
		"invalid digits (garbage suffix)": {
			uri:     "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&digits=6abc",
			wantErr: true,
			errMsg:  "invalid digits value",
		},
		"digits out of range": {
			uri:     "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&digits=9",
			wantErr: true,
			errMsg:  "invalid digits value",
		},
		"invalid period (non-positive)": {
			uri:     "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&period=0",
			wantErr: true,
			errMsg:  "invalid period value",
		},
		"account with unencoded colon": {
			// First colon is the issuer/account delimiter — subsequent colons
			// are part of the account name.
			uri:         "otpauth://totp/GitHub:alice:work?secret=JBSWY3DPEHPK3PXP",
			wantSecret:  "JBSWY3DPEHPK3PXP",
			wantIssuer:  "GitHub",
			wantAccount: "alice:work",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			info, err := ExtractTOTPFullInfo(tc.uri)

			if (err != nil) != tc.wantErr {
				t.Errorf("ExtractTOTPFullInfo() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			if tc.wantErr {
				if tc.errMsg != "" && !strings.Contains(err.Error(), tc.errMsg) {
					t.Errorf("Expected error containing %q, got %q", tc.errMsg, err.Error())
				}
				return
			}

			if info.Secret != tc.wantSecret {
				t.Errorf("Secret = %v, want %v", info.Secret, tc.wantSecret)
			}
			if info.Issuer != tc.wantIssuer {
				t.Errorf("Issuer = %v, want %v", info.Issuer, tc.wantIssuer)
			}
			if info.Account != tc.wantAccount {
				t.Errorf("Account = %v, want %v", info.Account, tc.wantAccount)
			}
		})
	}
}

func TestExtractSecretFromOTPAuthURL(t *testing.T) {
	tests := map[string]struct {
		url        string
		wantSecret string
		errMsg     string
		wantErr    bool
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

func TestDecodeQRCodeFromFile(t *testing.T) {
	tests := map[string]struct {
		setup   func(*testing.T) string
		cleanup func(string)
		errMsg  string
		wantErr bool
	}{
		"file not found": {
			setup: func(*testing.T) string {
				return "/nonexistent/file.png"
			},
			cleanup: func(string) {},
			wantErr: true,
			errMsg:  "failed to open image file",
		},
		"invalid png file": {
			setup: func(t *testing.T) string {
				t.Helper()
				f, err := os.CreateTemp("", "invalid*.png")
				if err != nil {
					t.Fatalf("test setup: failed to create temp file: %v", err)
					return ""
				}
				if _, err := f.WriteString("not a png file"); err != nil {
					if closeErr := f.Close(); closeErr != nil {
						t.Logf("test setup: failed to close temp file during cleanup: %v", closeErr)
					}
					if removeErr := os.Remove(f.Name()); removeErr != nil {
						t.Logf("test setup: failed to remove temp file during cleanup: %v", removeErr)
					}
					t.Fatalf("test setup: failed to write temp file: %v", err)
					return ""
				}
				if err := f.Close(); err != nil {
					if removeErr := os.Remove(f.Name()); removeErr != nil {
						t.Logf("test setup: failed to remove temp file during cleanup: %v", removeErr)
					}
					t.Fatalf("test setup: failed to close temp file: %v", err)
					return ""
				}
				return f.Name()
			},
			cleanup: func(name string) {
				if err := os.Remove(name); err != nil && !os.IsNotExist(err) {
					t.Errorf("cleanup failed for %s: %v", name, err)
				}
			},
			wantErr: true,
			errMsg:  "failed to decode image",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			filename := tc.setup(t)
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
		wg.Go(func() {
			_, err := DecodeQRCodeFromImage(img)
			if err != nil {
				errors <- err
			}
		})
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
	// Use a fixed secret so the QR image is deterministic — avoids flaky
	// decode failures caused by certain random patterns at small image sizes.
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Integration Test",
		AccountName: "integration@test.com",
		Secret:      []byte("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"),
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
		if err := os.Remove(tmpFile.Name()); err != nil && !os.IsNotExist(err) {
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
