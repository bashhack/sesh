// mock-aws-cli.go - Simulates AWS CLI for testing sesh without real AWS setup
//
// Usage:
//   1. Add this script's directory to your PATH (before real aws):
//      export PATH="/path/to/sesh/scripts:$PATH"
//   2. Make it executable:
//      go build -o aws mock-aws-cli.go && chmod +x aws
//   3. Use sesh normally:
//      sesh aws setup
//      sesh aws

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
	mockSecretKey   = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYMOCKEXAMPLE" // #nosec G101 - This is a mock key for testing
	mockSessionName = "mock-session"
)

// CallerIdentity mirrors the aws sts get-caller-identity JSON response.
type CallerIdentity struct {
	UserId  string `json:"UserId"`
	Account string `json:"Account"`
	Arn     string `json:"Arn"`
}

// MFADevice mirrors a single entry in the aws iam list-mfa-devices response.
type MFADevice struct {
	UserName     string `json:"UserName"`
	SerialNumber string `json:"SerialNumber"`
	EnableDate   string `json:"EnableDate"`
}

// MFADeviceList mirrors the aws iam list-mfa-devices JSON response.
type MFADeviceList struct {
	MFADevices []MFADevice `json:"MFADevices"`
}

// Credentials mirrors the temporary credentials in the STS session token response.
type Credentials struct {
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken"`
	Expiration      string `json:"Expiration"`
}

// SessionCredentials mirrors the aws sts get-session-token JSON response.
type SessionCredentials struct {
	Credentials Credentials `json:"Credentials"`
}

// positional is the command line without the global options the real
// CLI takes anywhere (--profile, --output, --query, --region), which come
// before or after the command.
var positional []string

// profile is the profile the command is for: --profile, AWS_PROFILE, or
// default.
var profile string

// loginProfile says whether the profile signs in with aws login: those in
// MOCK_AWS_LOGIN_PROFILES, comma-separated.
func loginProfile() bool {
	return strings.Contains(","+os.Getenv("MOCK_AWS_LOGIN_PROFILES")+",", ","+profile+",")
}

// sessionFile is where the mock keeps a login profile's session: present
// after aws login, gone after aws logout. MOCK_AWS_STATE names the folder.
func sessionFile() string {
	dir := os.Getenv("MOCK_AWS_STATE")
	if dir == "" {
		dir = os.TempDir()
	}
	return dir + "/mock-aws-login-" + profile
}

// main dispatches mock AWS CLI commands based on the first argument.
func main() {
	profile = os.Getenv("AWS_PROFILE")
	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--profile", "--output", "--query", "--region":
			if os.Args[i] == "--profile" && i+1 < len(os.Args) {
				profile = os.Args[i+1]
			}
			i++
		default:
			positional = append(positional, os.Args[i])
		}
	}
	if len(positional) < 1 {
		fmt.Fprintf(os.Stderr, "%sError: aws requires at least one argument%s\n", colorRed, colorReset)
		os.Exit(1)
	}
	// Profiles the mock knows: MOCK_AWS_PROFILES, comma-separated, or
	// default and work. Another fails as the real CLI does.
	known := os.Getenv("MOCK_AWS_PROFILES")
	if known == "" {
		known = "default,work"
	}
	if profile != "" && !strings.Contains(","+known+",", ","+profile+",") {
		fmt.Fprintf(os.Stderr, "\nThe config profile (%s) could not be found\n", profile)
		os.Exit(255)
	}

	command := positional[0]
	if profile == "" {
		profile = "default"
	}

	switch command {
	case "sts":
		handleSTS()
	case "iam":
		handleIAM()
	case "configure":
		handleConfigure()
	case "login":
		if !loginProfile() {
			fmt.Fprintf(os.Stderr, "\nThe profile (%s) isn't set up for aws login in this mock: add it to MOCK_AWS_LOGIN_PROFILES\n", profile)
			os.Exit(255)
		}
		fmt.Println("Attempting to open your default browser. (mock: signed in at once)")
		if err := os.WriteFile(sessionFile(), nil, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("Updated profile %s to use arn:aws:iam::%s:user/%s credentials.\n", profile, mockAccountID, mockUsername)
	case "logout":
		_ = os.Remove(sessionFile())
		fmt.Printf("Removed cached login credentials for profile '%s'.\n", profile)
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

// handleSTS routes STS subcommands (get-caller-identity, get-session-token).
func handleSTS() {
	if len(positional) < 2 {
		fmt.Fprintf(os.Stderr, "%sError: sts requires a subcommand%s\n", colorRed, colorReset)
		os.Exit(1)
	}

	subcommand := positional[1]

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

// handleIAM routes IAM subcommands (list-mfa-devices).
func handleIAM() {
	if len(positional) < 2 {
		fmt.Fprintf(os.Stderr, "%sError: iam requires a subcommand%s\n", colorRed, colorReset)
		os.Exit(1)
	}

	subcommand := positional[1]

	switch subcommand {
	case "list-mfa-devices":
		listMFADevices()
	default:
		fmt.Fprintf(os.Stderr, "%sError: Unknown iam subcommand '%s'%s\n", colorRed, subcommand, colorReset)
		os.Exit(1)
	}
}

// handleConfigure routes configure subcommands (get).
func handleConfigure() {
	if len(positional) < 2 {
		fmt.Fprintf(os.Stderr, "%sError: configure requires a subcommand%s\n", colorRed, colorReset)
		os.Exit(1)
	}

	subcommand := positional[1]

	switch subcommand {
	case "get":
		if len(positional) < 3 {
			fmt.Fprintf(os.Stderr, "%sError: configure get requires a key%s\n", colorRed, colorReset)
			os.Exit(1)
		}
		switch key := positional[2]; {
		case key == "region":
			fmt.Println(mockRegion)
		case key == "login_session" && loginProfile():
			fmt.Printf("arn:aws:iam::%s:user/%s\n", mockAccountID, mockUsername)
		default:
			// The real CLI says nothing for a setting that isn't there.
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "%sError: Unknown configure subcommand '%s'%s\n", colorRed, subcommand, colorReset)
		os.Exit(1)
	}
}

// getCallerIdentity returns a mock STS caller identity response.
func getCallerIdentity() {
	// Simulate a brief network delay
	time.Sleep(100 * time.Millisecond)

	if loginProfile() {
		if _, err := os.Stat(sessionFile()); err != nil {
			fmt.Fprintf(os.Stderr, "\naws: [ERROR]: Error loading login session token: Unable to load a existing login session for session arn:aws:iam::%s:user/%s, Please reauthenticate with 'aws login'.\n", mockAccountID, mockUsername)
			os.Exit(255)
		}
	}

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

	if flagValue("--query") == "Arn" && flagValue("--output") == "text" {
		fmt.Println(identity.Arn)
		return
	}
	output, _ := json.MarshalIndent(identity, "", "    ")
	fmt.Println(string(output))
}

// flagValue is the value given after flag on the command line, or "".
func flagValue(flag string) string {
	for i, arg := range os.Args {
		if arg == flag && i+1 < len(os.Args) {
			return os.Args[i+1]
		}
	}
	return ""
}

// listMFADevices returns a mock IAM list-mfa-devices response.
func listMFADevices() {
	// Simulate a brief network delay
	time.Sleep(100 * time.Millisecond)

	// Check for flags
	var username string
	var query string
	var outputFormat string = "json" // default

	for i, arg := range os.Args {
		if arg == "--user-name" && i+1 < len(os.Args) {
			username = os.Args[i+1]
		}
		if arg == "--query" && i+1 < len(os.Args) {
			query = os.Args[i+1]
		}
		if arg == "--output" && i+1 < len(os.Args) {
			outputFormat = os.Args[i+1]
		}
	}

	if username == "" {
		username = mockUsername
	}

	devices := MFADeviceList{
		MFADevices: []MFADevice{
			{
				UserName:     username,
				SerialNumber: "arn:aws:iam::" + mockAccountID + ":u2f/user/" + username + "/securitykey-MOCKEXAMPLE",
				EnableDate:   "2024-01-10T10:00:00Z",
			},
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

	// Handle query parameter
	if query == "MFADevices[].SerialNumber" && outputFormat == "text" {
		// Output just the serial numbers in text format
		for i, device := range devices.MFADevices {
			if i > 0 {
				fmt.Print("\t")
			}
			fmt.Print(device.SerialNumber)
		}
		if len(devices.MFADevices) > 0 {
			fmt.Println()
		}
		return
	}

	// Default JSON output
	output, _ := json.MarshalIndent(devices, "", "    ")
	fmt.Println(string(output))
}

// getSessionToken returns mock temporary session credentials after validating the TOTP code.
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

	// MOCK_AWS_REFUSE_CODE refuses every code, as AWS refuses one used
	// already, with AWS's own words.
	if os.Getenv("MOCK_AWS_REFUSE_CODE") == "true" {
		fmt.Fprintf(os.Stderr, "\nAn error occurred (AccessDenied) when calling the GetSessionToken operation: MultiFactorAuthentication failed with invalid MFA one time pass code.\n")
		os.Exit(254)
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
			AccessKeyID:     "ASIAMOCKTEMPORARY" + strings.ToUpper(tokenCode[:3]),
			SecretAccessKey: "mockTemporarySecretKey" + tokenCode,
			SessionToken:    "FwoGZXIvYXdzEMOCKEXAMPLETOKEN==" + tokenCode,
			Expiration:      expiration,
		},
	}

	output, _ := json.MarshalIndent(creds, "", "    ")
	fmt.Println(string(output))
}

// isValidTokenCode checks that a TOTP code is exactly 6 digits.
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
