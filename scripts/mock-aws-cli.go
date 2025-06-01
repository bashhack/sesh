// mock-aws-cli.go - Simulates AWS CLI for testing sesh without real AWS setup
//
// Usage:
//   1. Add this script's directory to your PATH (before real aws):
//      export PATH="/path/to/sesh/scripts:$PATH"
//   2. Make it executable:
//      go build -o aws mock-aws-cli.go && chmod +x aws
//   3. Use sesh normally:
//      sesh --service aws --setup
//      sesh --service aws

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	// ANSI color codes
	colorReset  = "\033[0m"
	colorGreen  = "\033[0;32m"
	colorRed    = "\033[0;31m"
	colorYellow = "\033[1;33m"
	colorBlue   = "\033[0;34m"
)

// Mock data
const (
	mockAccountID   = "123456789012"
	mockUserID      = "AIDAMOCKUSER123456"
	mockUsername    = "mockuser"
	mockRegion      = "us-east-1"
	mockMFASerial   = "arn:aws:iam::123456789012:mfa/mockuser"
	mockAccessKey   = "AKIAMOCKEXAMPLE"
	mockSecretKey   = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYMOCKEXAMPLE"
	mockSessionName = "mock-session"
)

type CallerIdentity struct {
	UserId  string `json:"UserId"`
	Account string `json:"Account"`
	Arn     string `json:"Arn"`
}

type MFADevice struct {
	UserName     string `json:"UserName"`
	SerialNumber string `json:"SerialNumber"`
	EnableDate   string `json:"EnableDate"`
}

type MFADeviceList struct {
	MFADevices []MFADevice `json:"MFADevices"`
}

type Credentials struct {
	AccessKeyId     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken"`
	Expiration      string `json:"Expiration"`
}

type SessionCredentials struct {
	Credentials Credentials `json:"Credentials"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "%sError: aws requires at least one argument%s\n", colorRed, colorReset)
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "sts":
		handleSTS()
	case "iam":
		handleIAM()
	case "configure":
		handleConfigure()
	case "--version":
		fmt.Println("aws-cli/2.13.0 Python/3.11.4 Darwin/23.0.0 exe/x86_64 prompt/off")
	default:
		fmt.Fprintf(os.Stderr, "%sError: Unknown command '%s'%s\n", colorRed, command, colorReset)
		fmt.Fprintf(os.Stderr, "This is a mock AWS CLI for testing sesh. Supported commands:\n")
		fmt.Fprintf(os.Stderr, "  - aws sts get-caller-identity\n")
		fmt.Fprintf(os.Stderr, "  - aws sts get-session-token\n")
		fmt.Fprintf(os.Stderr, "  - aws iam list-mfa-devices\n")
		fmt.Fprintf(os.Stderr, "  - aws configure get region\n")
		os.Exit(1)
	}
}

func handleSTS() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "%sError: sts requires a subcommand%s\n", colorRed, colorReset)
		os.Exit(1)
	}

	subcommand := os.Args[2]

	switch subcommand {
	case "get-caller-identity":
		getCallerIdentity()
	case "get-session-token":
		getSessionToken()
	default:
		fmt.Fprintf(os.Stderr, "%sError: Unknown sts subcommand '%s'%s\n", colorRed, subcommand, colorReset)
		os.Exit(1)
	}
}

func handleIAM() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "%sError: iam requires a subcommand%s\n", colorRed, colorReset)
		os.Exit(1)
	}

	subcommand := os.Args[2]

	switch subcommand {
	case "list-mfa-devices":
		listMFADevices()
	default:
		fmt.Fprintf(os.Stderr, "%sError: Unknown iam subcommand '%s'%s\n", colorRed, subcommand, colorReset)
		os.Exit(1)
	}
}

func handleConfigure() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "%sError: configure requires a subcommand%s\n", colorRed, colorReset)
		os.Exit(1)
	}

	subcommand := os.Args[2]

	switch subcommand {
	case "get":
		if len(os.Args) < 4 {
			fmt.Fprintf(os.Stderr, "%sError: configure get requires a key%s\n", colorRed, colorReset)
			os.Exit(1)
		}
		key := os.Args[3]
		if key == "region" {
			fmt.Println(mockRegion)
		} else {
			fmt.Fprintf(os.Stderr, "%sError: Unknown configure key '%s'%s\n", colorRed, key, colorReset)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "%sError: Unknown configure subcommand '%s'%s\n", colorRed, subcommand, colorReset)
		os.Exit(1)
	}
}

func getCallerIdentity() {
	// Simulate a brief network delay
	time.Sleep(100 * time.Millisecond)

	// Check if we're in a failed state (for testing error scenarios)
	if os.Getenv("MOCK_AWS_FAIL") == "true" {
		fmt.Fprintf(os.Stderr, "\nAn error occurred (ExpiredToken) when calling the GetCallerIdentity operation: The security token included in the request is expired\n")
		os.Exit(1)
	}

	identity := CallerIdentity{
		UserId:  mockUserID,
		Account: mockAccountID,
		Arn:     fmt.Sprintf("arn:aws:iam::%s:user/%s", mockAccountID, mockUsername),
	}

	output, _ := json.MarshalIndent(identity, "", "    ")
	fmt.Println(string(output))
}

func listMFADevices() {
	// Simulate a brief network delay
	time.Sleep(100 * time.Millisecond)

	// Check for --user-name flag
	var username string
	for i, arg := range os.Args {
		if arg == "--user-name" && i+1 < len(os.Args) {
			username = os.Args[i+1]
			break
		}
	}

	if username == "" {
		username = mockUsername
	}

	devices := MFADeviceList{
		MFADevices: []MFADevice{
			{
				UserName:     username,
				SerialNumber: mockMFASerial,
				EnableDate:   "2024-01-15T10:00:00Z",
			},
		},
	}

	// If MOCK_AWS_NO_MFA is set, return empty device list
	if os.Getenv("MOCK_AWS_NO_MFA") == "true" {
		devices.MFADevices = []MFADevice{}
	}

	output, _ := json.MarshalIndent(devices, "", "    ")
	fmt.Println(string(output))
}

func getSessionToken() {
	// Simulate a brief network delay
	time.Sleep(200 * time.Millisecond)

	// Parse arguments
	var serialNumber, tokenCode string
	for i, arg := range os.Args {
		if arg == "--serial-number" && i+1 < len(os.Args) {
			serialNumber = os.Args[i+1]
		}
		if arg == "--token-code" && i+1 < len(os.Args) {
			tokenCode = os.Args[i+1]
		}
	}

	// Validate MFA if provided
	if serialNumber != "" && tokenCode == "" {
		fmt.Fprintf(os.Stderr, "\nAn error occurred (MissingParameter) when calling the GetSessionToken operation: Missing required parameter TokenCode\n")
		os.Exit(1)
	}

	// Simulate invalid token code
	if tokenCode != "" && !isValidTokenCode(tokenCode) {
		fmt.Fprintf(os.Stderr, "\nAn error occurred (InvalidUserType.Token) when calling the GetSessionToken operation: The MFA token code is invalid\n")
		os.Exit(1)
	}

	// Generate mock session credentials
	expiration := time.Now().Add(12 * time.Hour).UTC().Format(time.RFC3339)
	
	creds := SessionCredentials{
		Credentials: Credentials{
			AccessKeyId:     "ASIAMOCKTEMPORARY" + strings.ToUpper(tokenCode[:3]),
			SecretAccessKey: "mockTemporarySecretKey" + tokenCode,
			SessionToken:    "FwoGZXIvYXdzEMOCKEXAMPLETOKEN==" + tokenCode,
			Expiration:      expiration,
		},
	}

	output, _ := json.MarshalIndent(creds, "", "    ")
	fmt.Println(string(output))
}

func isValidTokenCode(code string) bool {
	// Simple validation: 6 digits
	if len(code) != 6 {
		return false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}