// +build ignore

package main

import (
	"image/png"
	"os"
	
	"github.com/skip2/go-qrcode"
)

func main() {
	// Create a valid TOTP URL
	otpauthURL := "otpauth://totp/TestService:testuser@example.com?secret=JBSWY3DPEHPK3PXP&issuer=TestService"
	
	// Generate QR code
	qr, err := qrcode.New(otpauthURL, qrcode.Medium)
	if err != nil {
		panic(err)
	}
	
	// Create the file
	file, err := os.Create("test_qr.png")
	if err != nil {
		panic(err)
	}
	defer file.Close()
	
	// Write the QR code as PNG
	qr.DisableBorder = true
	if err := qr.Write(256, file); err != nil {
		panic(err)
	}
	
	println("Generated test_qr.png")
}