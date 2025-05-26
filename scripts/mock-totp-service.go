// mock-totp-service.go - Simulates an external TOTP service for testing sesh
//
// Usage:
//   go run mock-totp-service.go [SERVICE_NAME] [ACCOUNT_NAME]
//
// Examples:
//   go run mock-totp-service.go                    # Creates TestService with testuser@example.com
//   go run mock-totp-service.go GitHub             # Creates GitHub with testuser@example.com
//   go run mock-totp-service.go Datadog ops@company.com  # Creates Datadog with ops@company.com

package main

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"net/url"
	"os"
	
	"github.com/skip2/go-qrcode"
)

const (
	// ANSI color codes
	colorReset  = "\033[0m"
	colorGreen  = "\033[0;32m"
	colorBlue   = "\033[0;34m"
	colorYellow = "\033[1;33m"
)

func generateSecret() (string, error) {
	// Generate 16 random bytes (128 bits)
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	
	// Encode as base32 and remove padding
	secret := base32.StdEncoding.EncodeToString(bytes)
	// Remove trailing '=' padding
	for len(secret) > 0 && secret[len(secret)-1] == '=' {
		secret = secret[:len(secret)-1]
	}
	
	return secret, nil
}

func generateTOTPURI(serviceName, accountName, secret string) string {
	// Build the TOTP URI according to the spec
	// otpauth://totp/LABEL?secret=SECRET&issuer=ISSUER
	
	label := fmt.Sprintf("%s:%s", serviceName, accountName)
	
	params := url.Values{}
	params.Set("secret", secret)
	params.Set("issuer", serviceName)
	
	u := &url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     "/" + label,
		RawQuery: params.Encode(),
	}
	
	return u.String()
}

func printQRCode(uri string) error {
	// Generate QR code in terminal using ASCII
	qr, err := qrcode.New(uri, qrcode.Low)
	if err != nil {
		return err
	}
	
	// Get the QR code as a string with ASCII blocks
	fmt.Println(qr.ToSmallString(false))
	
	return nil
}

func main() {
	// Parse command line arguments
	serviceName := "TestService"
	accountName := "testuser@example.com"
	
	if len(os.Args) > 1 {
		serviceName = os.Args[1]
	}
	if len(os.Args) > 2 {
		accountName = os.Args[2]
	}
	
	// Generate secret
	secret, err := generateSecret()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating secret: %v\n", err)
		os.Exit(1)
	}
	
	// Generate TOTP URI
	uri := generateTOTPURI(serviceName, accountName, secret)
	
	// Print header
	fmt.Printf("%s╔══════════════════════════════════════════════════════════════╗%s\n", colorGreen, colorReset)
	fmt.Printf("%s║           Mock TOTP Service: %-30s ║%s\n", colorGreen, serviceName, colorReset)
	fmt.Printf("%s╚══════════════════════════════════════════════════════════════╝%s\n", colorGreen, colorReset)
	fmt.Println()
	
	// Print QR code and secret side by side (Amazon-style)
	fmt.Printf("%s1. Scan this QR code with sesh:%s\n", colorBlue, colorReset)
	fmt.Println()
	
	// Print QR code
	if err := printQRCode(uri); err != nil {
		fmt.Fprintf(os.Stderr, "Error generating QR code: %v\n", err)
	}
	
	fmt.Println()
	fmt.Printf("%s2. Or enter this secret manually:%s\n", colorBlue, colorReset)
	fmt.Println()
	fmt.Printf("   %s%s%s\n", colorYellow, secret, colorReset)
	fmt.Println()
	fmt.Printf("   Account: %s\n", accountName)
	fmt.Println()
	
	// Simplified setup instructions
	fmt.Printf("%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n", colorGreen, colorReset)
	fmt.Printf("%sSetup:%s  sesh --service totp --setup\n", colorGreen, colorReset)
	fmt.Printf("%sTest:%s   sesh --service totp --service-name %s\n", colorGreen, colorReset, serviceName)
	fmt.Printf("%sClip:%s   sesh --service totp --service-name %s --clip\n", colorGreen, colorReset, serviceName)
}