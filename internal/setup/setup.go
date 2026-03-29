// Package setup provides interactive setup flows for configuring TOTP and AWS MFA credentials.
package setup

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/bashhack/sesh/internal/constants"
	"github.com/bashhack/sesh/internal/env"
	"github.com/bashhack/sesh/internal/keychain"
	"github.com/bashhack/sesh/internal/keyformat"
	"github.com/bashhack/sesh/internal/qrcode"
	"github.com/bashhack/sesh/internal/secure"
	"github.com/bashhack/sesh/internal/totp"
)

// runCommand executes a command and returns its output.
// It is a variable so we can swap it out in tests.
var runCommand = func(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).Output()
}

// readPassword is a variable so we can swap it out in tests
var readPassword = term.ReadPassword

// scanQRCode is a variable so we can swap it out in tests
var scanQRCode = qrcode.ScanQRCode

// timeSleep is a variable so we can swap it out in tests
var timeSleep = time.Sleep

// validateAndNormalizeSecret is a variable so we can swap it out in tests
var validateAndNormalizeSecret = totp.ValidateAndNormalizeSecret

// generateConsecutiveCodes is a variable so we can swap it out in tests
var generateConsecutiveCodes = totp.GenerateConsecutiveCodes

// getCurrentUser is a variable so we can swap it out in tests
var getCurrentUser = env.GetCurrentUser

// execLookPath is a variable so we can swap it out in tests
var execLookPath = exec.LookPath

// readLine reads a line of input, returning the trimmed string or an error.
func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("failed to read input: %w", err)
	}
	return strings.TrimSpace(line), nil
}

// waitForEnter blocks until the user presses Enter.
func waitForEnter(r *bufio.Reader) error {
	_, err := r.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}
	return nil
}

// AWS Setup Handler

// AWSSetupHandler implements SetupHandler for AWS
type AWSSetupHandler struct {
	keychainProvider keychain.Provider
	reader           *bufio.Reader
}

// NewAWSSetupHandler creates a new AWS setup handler
func NewAWSSetupHandler(provider keychain.Provider) *AWSSetupHandler {
	return &AWSSetupHandler{
		keychainProvider: provider,
		reader:           bufio.NewReader(os.Stdin),
	}
}

// ServiceName returns the name of the service
func (h *AWSSetupHandler) ServiceName() string {
	return "aws"
}

// Helper to create service names with proper profile handling
func (h *AWSSetupHandler) createServiceName(prefix, profile string) (string, error) {
	if profile == "" {
		profile = "default"
	}
	return keyformat.Build(prefix, profile)
}

// runAWSCommand executes an AWS CLI command with the given profile and args,
// returning its output. It automatically adds the profile flag if provided.
func (h *AWSSetupHandler) runAWSCommand(profile string, args ...string) ([]byte, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("runAWSCommand requires at least one argument")
	}
	if profile != "" {
		profArgs := append([]string{args[0], "--profile", profile}, args[1:]...)
		return runCommand("aws", profArgs...)
	}
	return runCommand("aws", args...)
}

// verifyAWSCredentials checks if AWS credentials are properly configured
// It tries to get the caller identity and returns the user ARN if successful
// Returns the user ARN and any error that occurred
func (h *AWSSetupHandler) verifyAWSCredentials(profile string) (string, error) {
	output, err := h.runAWSCommand(profile, "sts", "get-caller-identity", "--query", "Arn", "--output", "text")
	if err != nil {
		return "", fmt.Errorf("failed to get AWS identity (make sure your AWS credentials are configured with 'aws configure'): %w", err)
	}

	userArn := strings.TrimSpace(string(output))

	fmt.Printf("✅ Found AWS identity: %s\n", userArn)

	return userArn, nil
}

// captureMFASecret guides the user through capturing the MFA secret
// Options include manual entry or QR code scanning
// Returns the captured secret string and any error that occurred
func (h *AWSSetupHandler) captureMFASecret(choice string) (string, error) {
	var secretStr string

	switch choice {
	case "1": // Manual entry
		fmt.Println(`
5. On the 'Set up virtual MFA device' screen, DO NOT scan the QR code
6. Click 'Show secret key' and copy the secret key
		
❗ DO NOT COMPLETE THE AWS SETUP YET - we'll do that together`)

		fmt.Print("\n📋 Paste the secret key below and press Enter:\n→ ")
		secret, err := readPassword(syscall.Stdin)
		if err != nil {
			return "", fmt.Errorf("failed to read secret: %w", err)
		}
		fmt.Println("✓") // Visual confirmation that input was received

		defer secure.SecureZeroBytes(secret)
		secretStr = strings.TrimSpace(string(secret))

	case "2": // QR code capture flow with retry
		fmt.Println(`
5. Keep the QR code visible on your screen

❗ DO NOT COMPLETE THE AWS SETUP YET - we'll do that together`)

		var err error
		secretStr, err = h.captureAWSQRCodeWithFallback()
		if err != nil {
			return "", err
		}

	default:
		return "", fmt.Errorf("invalid choice, please select 1 or 2")
	}

	// Validate secret key format (basic check)
	if len(secretStr) < 16 {
		return "", fmt.Errorf("secret key seems too short (got %d chars). Please double-check and try again", len(secretStr))
	}

	return secretStr, nil
}

// captureAWSQRCodeWithFallback attempts AWS QR capture with retry and manual fallback
func (h *AWSSetupHandler) captureAWSQRCodeWithFallback() (string, error) {
	return captureQRWithRetry(h.reader, h.captureAWSManualEntry)
}

// captureAWSManualEntry handles manual AWS MFA secret entry
func (h *AWSSetupHandler) captureAWSManualEntry() (string, error) {
	fmt.Println(`
5. On the 'Set up virtual MFA device' screen, DO NOT scan the QR code
6. Click 'Show secret key' and copy the secret key
		
❗ DO NOT COMPLETE THE AWS SETUP YET - we'll do that together`)

	fmt.Print("\n📋 Paste the secret key below and press Enter:\n→ ")
	secret, err := readPassword(syscall.Stdin)
	if err != nil {
		return "", fmt.Errorf("failed to read secret: %w", err)
	}
	fmt.Println("✓") // Visual confirmation that input was received

	defer secure.SecureZeroBytes(secret)
	return strings.TrimSpace(string(secret)), nil
}

// setupMFAConsole generates TOTP codes and guides the user through AWS console setup
// It displays the codes and instructions for completing setup in the AWS console
// Returns any error that occurred during code generation
func (h *AWSSetupHandler) setupMFAConsole(secretStr string) error {
	// At the time of writing, AWS requires two codes during setup
	firstCode, secondCode, err := totp.GenerateConsecutiveCodes(secretStr)
	if err != nil {
		return fmt.Errorf("failed to generate TOTP codes: %w", err)
	}

	fmt.Printf(`✅ Generated TOTP codes for AWS setup
First code: %s
Second code: %s

IMPORTANT - FOLLOW THESE STEPS:
1. Enter these codes in the AWS Console
2. Click the "Add MFA" button to complete setup
3. Wait for confirmation in the AWS console that setup is complete

Press Enter ONLY AFTER you see "MFA device was successfully assigned" in AWS console...`, firstCode, secondCode)
	if err := waitForEnter(h.reader); err != nil {
		return err
	}

	return nil
}

// selectMFADevice handles listing and selecting an MFA device for the user
// It queries the AWS API for MFA devices and guides the user through selecting one
// If no devices are found, it provides retry and manual entry options
// Returns the MFA device ARN and any error that occurred
func (h *AWSSetupHandler) selectMFADevice(profile string) (string, error) {

	mfaOutput, err := h.runAWSCommand(profile, "iam", "list-mfa-devices", "--query", "MFADevices[].SerialNumber", "--output", "text")
	var mfaArn string

	// Try to fetch MFA devices, with retries if none are found
	maxRetries := 2
	retryCount := 0

mfaDeviceLoop:
	for {
		if err == nil && strings.TrimSpace(string(mfaOutput)) != "" {
			// MFA devices were found, process them
			mfaDevices := strings.Split(strings.TrimSpace(string(mfaOutput)), "\t")

			// Always show the list of devices and let the user choose, even if there's only one.
			// This handles cases where they already had an MFA device and the new one isn't
			// showing up yet, or they had a single existing device that isn't the one they just created.
			fmt.Println("\nFound MFA device(s):")
			for i, device := range mfaDevices {
				fmt.Printf("%d: %s\n", i+1, device)
			}

		selectionPrompt:
			fmt.Print("\nChoose the MFA device you just created (1-" + fmt.Sprintf("%d", len(mfaDevices)) +
				"), 'r' to refresh the list, or 'm' to enter manually: ")
			choice, err := readLine(h.reader)
			if err != nil {
				return "", err
			}

			switch choice {
			case "r", "R":
				// Refresh MFA devices list
				fmt.Println("\n🔄 Refreshing MFA device list...")
				mfaOutput, err = h.runAWSCommand(profile, "iam", "list-mfa-devices", "--query", "MFADevices[].SerialNumber", "--output", "text")
				if err != nil || strings.TrimSpace(string(mfaOutput)) == "" {
					fmt.Println("❗ No MFA devices found after refresh.")
					// Continue to the retry options below
					break
				}

				// Show updated list of devices and go back to selection prompt
				mfaDevices = strings.Split(strings.TrimSpace(string(mfaOutput)), "\t")
				fmt.Println("\nFound MFA device(s) after refresh:")
				for i, device := range mfaDevices {
					fmt.Printf("%d: %s\n", i+1, device)
				}
				goto selectionPrompt

			case "m", "M":
				// Manual entry with validation
				var err error
				mfaArn, err = h.promptForMFAARN()
				if err != nil {
					return "", err
				}
				break mfaDeviceLoop // Exit the entire loop when we've manually entered ARN

			default:
				// Try to parse as number
				var index int
				_, err := fmt.Sscanf(choice, "%d", &index)
				if err != nil || index < 1 || index > len(mfaDevices) {
					fmt.Println("\n❌ Invalid choice. Please select a number from the list, 'r' to refresh, or 'm' for manual entry.")
					goto selectionPrompt
				}

				mfaArn = mfaDevices[index-1]
				fmt.Printf("✅ Selected MFA device: %s\n", mfaArn)
				// MFA device successfully selected
				break mfaDeviceLoop // Exit the entire for loop with our selected device
			}
		}

		// No MFA devices found or error occurred
		if retryCount >= maxRetries {
			// We've exhausted our retries, fall back to manual entry with validation
			fmt.Println("\n❗ No MFA devices found after multiple attempts. You'll need to provide your MFA ARN manually.")

			var err error
			mfaArn, err = h.promptForMFAARN()
			if err != nil {
				return "", err
			}
			break mfaDeviceLoop
		}

		// Offer retry options
		fmt.Println(`
❓ No MFA devices were found. This is likely because:
   • AWS hasn't finished registering your MFA device yet (can take a few seconds)
   • You may have skipped clicking "Add MFA" in the AWS console

What would you like to do?
1: Wait 5 seconds and try again (recommended)
2: Return to AWS Console to complete setup, then try again
3: Enter your MFA ARN manually
Enter your choice (1-3): `)

		var retryChoice string
		retryChoice, err = readLine(h.reader)
		if err != nil {
			return "", err
		}

		switch retryChoice {
		case "1": // Wait and retry
			fmt.Println("\n⏳ Waiting 5 seconds for AWS to register your MFA device...")
			timeSleep(5 * time.Second)

			// Try fetching the MFA device again
			mfaOutput, err = h.runAWSCommand(profile, "iam", "list-mfa-devices", "--query", "MFADevices[].SerialNumber", "--output", "text")
			retryCount++

		case "2": // Return to console
			fmt.Println(`
Please complete these steps in the AWS Console:
1. Make sure you've clicked "Add MFA" after entering the TOTP codes
2. Confirm you see "MFA device was successfully assigned" message
3. Press Enter when complete...`)
			if waitErr := waitForEnter(h.reader); waitErr != nil {
				return "", waitErr
			}

			// Try fetching again
			mfaOutput, err = h.runAWSCommand(profile, "iam", "list-mfa-devices", "--query", "MFADevices[].SerialNumber", "--output", "text")
			retryCount++

		case "3": // Manual entry with validation
			mfaArn, err = h.promptForMFAARN()
			if err != nil {
				return "", err
			}
			break mfaDeviceLoop // Exit the loop completely

		default: // Invalid input
			fmt.Println("\n❌ Invalid choice. Please select 1, 2, or 3.")
			// Stay in the loop and show the options again
		}
	}

	return mfaArn, nil
}

// promptForMFAARN prompts the user to enter an MFA ARN manually
// It validates the ARN format and ensures it's not empty
// Returns the validated MFA ARN string and any error that occurred
func (h *AWSSetupHandler) promptForMFAARN() (string, error) {

	for {
		fmt.Print("Enter your MFA ARN (format: arn:aws:iam::ACCOUNT_ID:mfa/USERNAME): ")
		mfaArn, err := h.reader.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("failed to read MFA ARN: %w", err)
		}
		mfaArn = strings.TrimSpace(mfaArn)

		if mfaArn == "" {
			fmt.Println("\u274c MFA ARN cannot be empty. Please enter a valid ARN.")
			continue
		}

		// Basic validation could be added here
		if !strings.HasPrefix(mfaArn, "arn:aws:iam::") || !strings.Contains(mfaArn, ":mfa/") {
			fmt.Println("\u274c Invalid ARN format. Please enter a valid MFA ARN.")
			continue
		}

		return mfaArn, nil
	}
}

// promptForMFASetupMethod displays instructions for AWS MFA setup and prompts
// the user to choose a method for capturing the secret
// Returns the user's choice as a string
func (h *AWSSetupHandler) promptForMFASetupMethod() (string, error) {
	fmt.Println(`
📱 Let's set up a virtual MFA device for your AWS account

1. Log in to the AWS Console at https://console.aws.amazon.com
2. Navigate to IAM → Users → Your Username → Security credentials
3. Under 'Multi-factor authentication (MFA)', click 'Assign MFA device'
4. Choose 'Virtual MFA device' and click 'Continue'

How would you like to capture the MFA secret?
1: Enter the secret key manually (click 'Show secret key' in AWS)
2: Capture QR code from screen (take a screenshot of the QR code)
Enter your choice (1-2): `)

	choice, err := readLine(h.reader)
	if err != nil {
		return "", err
	}

	if choice != "1" && choice != "2" {
		return "", fmt.Errorf("invalid choice, please select 1 or 2")
	}

	return choice, nil
}

// showSetupCompletionMessage displays the final success message with usage instructions
func (h *AWSSetupHandler) showSetupCompletionMessage(profile string) {
	fmt.Println(`
✅ Setup complete! You can now use 'sesh' to generate AWS temporary credentials.

🚀 Next steps:
1. Run 'sesh -service aws' to generate a temporary session token
2. The credentials will be automatically exported to your shell
3. You can now use AWS CLI commands with MFA security`)

	if profile == "" {
		fmt.Println(`
To use this setup, run without the --profile flag
(The default AWS profile will be used)`)
	} else {
		fmt.Printf("\nTo use this setup, run: sesh --profile %s\n", profile)
	}
}

// Setup performs the AWS MFA setup process through an interactive CLI flow.
// The method guides users through the following steps:
//  1. Verifies AWS CLI is installed
//  2. Collects the AWS profile name (or uses default)
//  3. Verifies AWS credentials by checking caller identity
//  4. Guides the user through setting up a virtual MFA device in AWS Console
//  5. Captures the MFA secret (either manually or via QR code)
//  6. Generates TOTP codes and helps with AWS Console MFA setup
//  7. Helps identify and select the newly created MFA device, with retry and refresh options
//  8. Stores the MFA secret and serial number securely in system keychain
//  9. Provides instructions for using the setup with the sesh command
//
// The flow includes multiple validation steps, error handling, and user guidance
// for common issues that might occur during setup, such as delayed MFA device
// registration in the AWS API.
//
// Returns an error if any step in the setup process fails. If successful,
// the user will be able to generate temporary AWS credentials with MFA protection
// using the 'sesh' command.
func (h *AWSSetupHandler) Setup() error {
	fmt.Println("🔐 Setting up AWS credentials...")

	_, err := execLookPath("aws")
	if err != nil {
		return fmt.Errorf("AWS CLI not found. Please install it first: https://aws.amazon.com/cli/")
	}

	fmt.Println("✅ AWS CLI is installed")

	fmt.Print("Enter AWS CLI profile name (leave empty for default): ")
	profile, err := readLine(h.reader)
	if err != nil {
		return err
	}

	// Check if entry already exists
	user, err := getCurrentUser()
	if err != nil {
		return fmt.Errorf("failed to get current user: %w", err)
	}

	serviceName, err := h.createServiceName(constants.AWSServicePrefix, profile)
	if err != nil {
		return fmt.Errorf("failed to build service key: %w", err)
	}
	existingSecret, err := h.keychainProvider.GetSecretString(user, serviceName)
	if err != nil && !errors.Is(err, keychain.ErrNotFound) {
		return fmt.Errorf("failed to check existing entry: %w", err)
	}

	if existingSecret != "" {
		// Entry exists, prompt for overwrite
		profileDisplay := profile
		if profileDisplay == "" {
			profileDisplay = "default"
		}

		fmt.Printf("\n⚠️  An entry already exists for AWS profile '%s'\n", profileDisplay)
		fmt.Print("\nOverwrite existing configuration? (y/N): ")

		response, readErr := readLine(h.reader)
		if readErr != nil {
			return readErr
		}
		response = strings.ToLower(response)

		if response != "y" && response != "yes" {
			fmt.Println("\n❌ Setup cancelled")
			return fmt.Errorf("setup cancelled by user")
		}
		fmt.Println() // Add spacing before continuing
	}

	_, err = h.verifyAWSCredentials(profile)
	if err != nil {
		return err
	}

	choice, err := h.promptForMFASetupMethod()
	if err != nil {
		return err
	}

	secretStr, err := h.captureMFASecret(choice)
	if err != nil {
		return err
	}

	// Validate and normalize the TOTP secret
	normalizedSecret, err := totp.ValidateAndNormalizeSecret(secretStr)
	if err != nil {
		return fmt.Errorf("invalid TOTP secret: %w", err)
	}
	secretStr = normalizedSecret

	err = h.setupMFAConsole(secretStr)
	if err != nil {
		return err
	}

	mfaArn, err := h.selectMFADevice(profile)
	if err != nil {
		return fmt.Errorf("failed to select MFA device: %w", err)
	}

	// Write MFA ARN first — if the main secret write fails afterward,
	// we avoid leaving an "existing" setup that blocks future runs.
	serialServiceName, err := h.createServiceName(constants.AWSServiceMFAPrefix, profile)
	if err != nil {
		return fmt.Errorf("failed to build MFA serial key: %w", err)
	}
	err = h.keychainProvider.SetSecretString(user, serialServiceName, mfaArn)
	if err != nil {
		return fmt.Errorf("failed to store MFA serial in keychain: %w", err)
	}

	serviceName, err = h.createServiceName(constants.AWSServicePrefix, profile)
	if err != nil {
		return fmt.Errorf("failed to build service key: %w", err)
	}
	err = h.keychainProvider.SetSecretString(user, serviceName, secretStr)
	if err != nil {
		return fmt.Errorf("failed to store secret in keychain: %w", err)
	}

	description := "AWS MFA"
	if profile != "" {
		description = fmt.Sprintf("AWS MFA for profile %s", profile)
	}

	err = h.keychainProvider.StoreEntryMetadata(constants.AWSServicePrefix, serviceName, user, description)
	if err != nil {
		fmt.Println("⚠️ Warning: Failed to store metadata. This entry might not appear when listing available AWS profiles.")
	}

	h.showSetupCompletionMessage(profile)

	return nil
}

// TOTP Setup Handler

// TOTPSetupHandler implements SetupHandler for TOTP
type TOTPSetupHandler struct {
	keychainProvider keychain.Provider
	reader           *bufio.Reader
}

// NewTOTPSetupHandler creates a new TOTP setup handler
func NewTOTPSetupHandler(provider keychain.Provider) *TOTPSetupHandler {
	return &TOTPSetupHandler{
		keychainProvider: provider,
		reader:           bufio.NewReader(os.Stdin),
	}
}

// ServiceName returns the name of the service
func (h *TOTPSetupHandler) ServiceName() string {
	return "totp"
}

// createTOTPServiceName creates a TOTP service name with proper profile handling
func (h *TOTPSetupHandler) createTOTPServiceName(serviceName, profile string) (string, error) {
	if profile == "" {
		return keyformat.Build(constants.TOTPServicePrefix, serviceName)
	}
	return keyformat.Build(constants.TOTPServicePrefix, serviceName, profile)
}

// promptForServiceName prompts the user to enter a service name and validates it
func (h *TOTPSetupHandler) promptForServiceName() (string, error) {
	fmt.Print("Enter name for this TOTP service: ")
	serviceName, err := readLine(h.reader)
	if err != nil {
		return "", err
	}

	if serviceName == "" {
		return "", fmt.Errorf("service name cannot be empty")
	}

	return serviceName, nil
}

// promptForProfile prompts the user to enter an optional profile name
func (h *TOTPSetupHandler) promptForProfile() (string, error) {
	fmt.Print("Enter profile name (optional, for multiple accounts with the same service): ")
	profile, err := readLine(h.reader)
	if err != nil {
		return "", err
	}
	return profile, nil
}

// promptForCaptureMethod prompts the user to choose how to capture the TOTP secret
func (h *TOTPSetupHandler) promptForCaptureMethod() (string, error) {
	fmt.Println()
	fmt.Println("How would you like to capture the TOTP secret?")
	fmt.Println("1: Enter the secret key manually")
	fmt.Println("2: Capture QR code from screen")
	fmt.Print("Enter your choice (1-2): ")
	choice, err := readLine(h.reader)
	if err != nil {
		return "", err
	}

	if choice != "1" && choice != "2" {
		return "", fmt.Errorf("invalid choice, please select 1 or 2")
	}

	return choice, nil
}

// captureTOTPSecret captures the TOTP secret using the specified method
func (h *TOTPSetupHandler) captureTOTPSecret(choice string) (string, error) {
	switch choice {
	case "1": // Manual entry
		return h.captureManualEntry()
	case "2": // QR code capture with retry + fallback
		return h.captureQRCodeWithFallback()
	default:
		return "", fmt.Errorf("invalid choice, please select 1 or 2")
	}
}

// captureQRCodeWithFallback attempts QR capture with retry and manual fallback
func (h *TOTPSetupHandler) captureQRCodeWithFallback() (string, error) {
	return captureQRWithRetry(h.reader, h.captureManualEntry)
}

// captureManualEntry handles manual secret entry with secure memory handling
func (h *TOTPSetupHandler) captureManualEntry() (string, error) {
	fmt.Print("\n📋 Enter or paste your TOTP secret key and press Enter:\n→ ")
	secret, err := readPassword(syscall.Stdin)
	if err != nil {
		return "", fmt.Errorf("failed to read secret: %w", err)
	}
	fmt.Println("✓") // Visual confirmation that input was received

	// Handle secret securely
	secretBytes := secret
	defer secure.SecureZeroBytes(secretBytes)
	return strings.TrimSpace(string(secretBytes)), nil
}

// showTOTPSetupCompletionMessage displays the final success message with usage instructions
func (h *TOTPSetupHandler) showTOTPSetupCompletionMessage(serviceName, profile string) {
	profileFlag := ""
	if profile != "" {
		profileFlag = fmt.Sprintf(" --profile '%s'", profile)
	}
	fmt.Println("✅ Setup complete! Generate TOTP codes with:")
	fmt.Printf("  sesh --service totp --service-name '%s'%s\n", serviceName, profileFlag)
	fmt.Println("Copy to clipboard with:")
	fmt.Printf("  sesh --service totp --service-name '%s'%s --clip\n", serviceName, profileFlag)
}

// Setup performs the TOTP setup
func (h *TOTPSetupHandler) Setup() error {
	fmt.Println("🔐 Setting up TOTP credentials...")

	serviceName, err := h.promptForServiceName()
	if err != nil {
		return err
	}

	profile, err := h.promptForProfile()
	if err != nil {
		return err
	}

	// Check if entry already exists
	user, err := getCurrentUser()
	if err != nil {
		return fmt.Errorf("failed to get current user: %w", err)
	}

	serviceKey, err := h.createTOTPServiceName(serviceName, profile)
	if err != nil {
		return fmt.Errorf("failed to build service key: %w", err)
	}
	existingSecret, err := h.keychainProvider.GetSecretString(user, serviceKey)
	if err != nil && !errors.Is(err, keychain.ErrNotFound) {
		return fmt.Errorf("failed to check existing entry: %w", err)
	}

	if existingSecret != "" {
		// Entry exists, prompt for overwrite
		fmt.Printf("\n⚠️  An entry already exists for service '%s'", serviceName)
		if profile != "" {
			fmt.Printf(" with profile '%s'", profile)
		}
		fmt.Println()
		fmt.Print("\nOverwrite existing configuration? (y/N): ")

		response, readErr := readLine(h.reader)
		if readErr != nil {
			return readErr
		}
		response = strings.ToLower(response)

		if response != "y" && response != "yes" {
			fmt.Println("\n❌ Setup cancelled")
			return fmt.Errorf("setup cancelled by user")
		}
		fmt.Println() // Add spacing before continuing
	}

	choice, err := h.promptForCaptureMethod()
	if err != nil {
		return err
	}

	secretStr, err := h.captureTOTPSecret(choice)
	if err != nil {
		return err
	}

	// Validate and normalize the TOTP secret
	normalizedSecret, err := validateAndNormalizeSecret(secretStr)
	if err != nil {
		return fmt.Errorf("invalid TOTP secret: %w", err)
	}
	secretStr = normalizedSecret

	// Generate two consecutive TOTP codes
	firstCode, secondCode, err := generateConsecutiveCodes(secretStr)
	if err != nil {
		return fmt.Errorf("failed to generate TOTP codes: %s", err)
	}

	// Build service key using consistent helper pattern
	serviceKey, err = h.createTOTPServiceName(serviceName, profile)
	if err != nil {
		return fmt.Errorf("failed to build service key: %w", err)
	}

	// Store the secret using the keychain provider
	err = h.keychainProvider.SetSecretString(user, serviceKey, secretStr)
	if err != nil {
		return fmt.Errorf("failed to store secret in keychain: %w", err)
	}

	// Store metadata for better organization and retrieval
	description := fmt.Sprintf("TOTP for %s", serviceName)
	if profile != "" {
		description = fmt.Sprintf("TOTP for %s profile %s", serviceName, profile)
	}

	// Store metadata using the keychain provider
	err = h.keychainProvider.StoreEntryMetadata(constants.TOTPServicePrefix, serviceKey, user, description)
	if err != nil {
		fmt.Println("⚠️ Warning: Failed to store metadata. This entry might not appear when listing available TOTP services.")
	}

	// Display the generated TOTP codes for setup verification
	fmt.Println("✅ Generated TOTP codes for verification:")
	fmt.Printf("   Current code: %s\n", firstCode)
	fmt.Printf("   Next code: %s\n", secondCode)
	fmt.Println("   (Use these codes if your service requires verification during setup)")
	fmt.Println()

	h.showTOTPSetupCompletionMessage(serviceName, profile)

	return nil
}

// captureQRWithRetry is a shared helper for QR code capture with retry logic
func captureQRWithRetry(reader *bufio.Reader, manualEntryFunc func() (string, error)) (string, error) {
	maxRetries := 2

	for attempt := 1; attempt <= maxRetries; attempt++ {
		fmt.Printf("📸 QR capture attempt %d/%d\n", attempt, maxRetries)
		fmt.Println("Position your cursor at the top-left of the QR code, then click and drag to the bottom-right")
		fmt.Print("Press Enter to activate screenshot mode...")
		if err := waitForEnter(reader); err != nil {
			return "", err
		}

		secretStr, err := scanQRCode()
		if err == nil {
			fmt.Println("✅ QR code successfully captured and decoded!")
			return secretStr, nil
		}

		fmt.Printf("❌ QR capture failed: %v\n", err)

		if attempt < maxRetries {
			fmt.Println("💡 Tips: Check screen brightness, QR code size, and cursor positioning")
			fmt.Print("Press Enter to try again, or 'm' to switch to manual entry: ")
			choice, readErr := readLine(reader)
			if readErr != nil {
				return "", readErr
			}
			if strings.EqualFold(choice, "m") {
				fmt.Println("Switching to manual entry...")
				return manualEntryFunc()
			}
		}
	}

	// Final fallback after all retries
	fmt.Println("\n❓ QR capture failed after multiple attempts.")
	fmt.Print("Would you like to enter the secret manually instead? (y/n): ")
	fallback, err := readLine(reader)
	if err != nil {
		return "", err
	}

	if strings.EqualFold(fallback, "y") {
		return manualEntryFunc()
	}

	return "", fmt.Errorf("QR capture failed after %d attempts and user declined manual entry", maxRetries)
}
