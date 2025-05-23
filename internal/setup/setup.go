package setup

import (
	"bufio"
	"fmt"
	"github.com/bashhack/sesh/internal/constants"
	"github.com/bashhack/sesh/internal/env"
	"github.com/bashhack/sesh/internal/keychain"
	"github.com/bashhack/sesh/internal/qrcode"
	"github.com/bashhack/sesh/internal/totp"
	"golang.org/x/term"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

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
func (h *AWSSetupHandler) createServiceName(prefix string, profile string) string {
	if profile == "" {
		return fmt.Sprintf("%s-default", prefix)
	}
	return fmt.Sprintf("%s-%s", prefix, profile)
}

// createAWSCommand creates an AWS CLI command with the given profile and args
// It automatically adds the profile flag if a profile is provided
// Returns an exec.Cmd object ready to be executed
func (h *AWSSetupHandler) createAWSCommand(profile string, args ...string) *exec.Cmd {
	if profile != "" {
		// Insert profile flag after the first argument (command)
		profArgs := append([]string{args[0], "--profile", profile}, args[1:]...)
		return exec.Command("aws", profArgs...)
	}
	return exec.Command("aws", args...)
}

// verifyAWSCredentials checks if AWS credentials are properly configured
// It tries to get the caller identity and returns the user ARN if successful
// Returns the user ARN and any error that occurred
func (h *AWSSetupHandler) verifyAWSCredentials(profile string) (string, error) {
	cmd := h.createAWSCommand(profile, "sts", "get-caller-identity", "--query", "Arn", "--output", "text")

	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get AWS identity: %w. Make sure your AWS credentials are configured with 'aws configure'.", err)
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
		
❗ DO NOT COMPLETE THE AWS SETUP YET - we'll do that together

Paste the secret key here (this will not be echoed): `)
		secret, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return "", fmt.Errorf("failed to read secret: %w", err)
		}
		fmt.Println() // Add a newline after hidden input

		secretStr = strings.TrimSpace(string(secret))

	case "2": // QR code capture flow
		fmt.Println(`
5. Keep the QR code visible on your screen
6. When ready, press Enter to activate screenshot mode

❗ DO NOT COMPLETE THE AWS SETUP YET - we'll do that together

Press Enter when you're ready to capture the QR code...`)
		h.reader.ReadString('\n')

		fmt.Println("📸 Position your cursor at the top-left of the QR code, then click and drag to the bottom-right")
		var err error
		secretStr, err = qrcode.ScanQRCode()
		if err != nil {
			return "", fmt.Errorf("failed to process QR code: %w", err)
		}
		fmt.Println("✅ QR code successfully captured and decoded!")

	default:
		return "", fmt.Errorf("invalid choice, please select 1 or 2")
	}

	// Validate secret key format (basic check)
	if len(secretStr) < 16 {
		return "", fmt.Errorf("secret key seems too short (got %d chars). Please double-check and try again", len(secretStr))
	}

	return secretStr, nil
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
	h.reader.ReadString('\n')

	return nil
}

// selectMFADevice handles listing and selecting an MFA device for the user
// It queries the AWS API for MFA devices and guides the user through selecting one
// If no devices are found, it provides retry and manual entry options
// Returns the MFA device ARN and any error that occurred
func (h *AWSSetupHandler) selectMFADevice(profile string) (string, error) {

	mfaCmd := h.createAWSCommand(profile, "iam", "list-mfa-devices", "--query", "MFADevices[].SerialNumber", "--output", "text")

	mfaOutput, err := mfaCmd.Output()
	var mfaArn string

	// Try to fetch MFA devices, with retries if none are found
	maxRetries := 2
	retryCount := 0

mfaDeviceLoop:
	for {
		if err == nil && len(strings.TrimSpace(string(mfaOutput))) > 0 {
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
			choice, _ := h.reader.ReadString('\n')
			choice = strings.TrimSpace(choice)

			switch choice {
			case "r", "R":
				// Refresh MFA devices list
				fmt.Println("\n🔄 Refreshing MFA device list...")
				mfaCmd = h.createAWSCommand(profile, "iam", "list-mfa-devices", "--query", "MFADevices[].SerialNumber", "--output", "text")

				mfaOutput, err = mfaCmd.Output()
				if err != nil || len(strings.TrimSpace(string(mfaOutput))) == 0 {
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

		retryChoice, _ := h.reader.ReadString('\n')
		retryChoice = strings.TrimSpace(retryChoice)

		switch retryChoice {
		case "1": // Wait and retry
			fmt.Println("\n⏳ Waiting 5 seconds for AWS to register your MFA device...")
			time.Sleep(5 * time.Second)

			// Try fetching the MFA device again
			mfaCmd = h.createAWSCommand(profile, "iam", "list-mfa-devices", "--query", "MFADevices[].SerialNumber", "--output", "text")
			mfaOutput, err = mfaCmd.Output()
			retryCount++

		case "2": // Return to console
			fmt.Println(`
Please complete these steps in the AWS Console:
1. Make sure you've clicked "Add MFA" after entering the TOTP codes
2. Confirm you see "MFA device was successfully assigned" message
3. Press Enter when complete...`)
			h.reader.ReadString('\n')

			// Try fetching again
			mfaCmd = h.createAWSCommand(profile, "iam", "list-mfa-devices", "--query", "MFADevices[].SerialNumber", "--output", "text")
			mfaOutput, err = mfaCmd.Output()
			retryCount++

		case "3": // Manual entry with validation
			var err error
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
		mfaArn, _ := h.reader.ReadString('\n')
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

	choice, _ := h.reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

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

	_, err := exec.LookPath("aws")
	if err != nil {
		return fmt.Errorf("AWS CLI not found. Please install it first: https://aws.amazon.com/cli/")
	}

	fmt.Println("✅ AWS CLI is installed")

	fmt.Print("Enter AWS CLI profile name (leave empty for default): ")
	profile, _ := h.reader.ReadString('\n')
	profile = strings.TrimSpace(profile)

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

	user, err := env.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("failed to get current user: %w", err)
	}

	serviceName := h.createServiceName(constants.AWSServicePrefix, profile)
	err = h.keychainProvider.SetSecretString(user, serviceName, secretStr)
	if err != nil {
		return fmt.Errorf("failed to store secret in keychain: %w", err)
	}

	serialServiceName := h.createServiceName(constants.AWSServiceMFAPrefix, profile)
	err = h.keychainProvider.SetSecretString(user, serialServiceName, mfaArn)
	if err != nil {
		return fmt.Errorf("failed to store MFA serial in keychain: %w", err)
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
func (h *TOTPSetupHandler) createTOTPServiceName(serviceName, profile string) string {
	if profile == "" {
		return fmt.Sprintf("sesh-totp-%s", serviceName)
	}
	return fmt.Sprintf("sesh-totp-%s-%s", serviceName, profile)
}

// promptForServiceName prompts the user to enter a service name and validates it
func (h *TOTPSetupHandler) promptForServiceName() (string, error) {
	fmt.Print("Enter name for this TOTP service: ")
	serviceName, _ := h.reader.ReadString('\n')
	serviceName = strings.TrimSpace(serviceName)

	if serviceName == "" {
		return "", fmt.Errorf("service name cannot be empty")
	}

	return serviceName, nil
}

// promptForProfile prompts the user to enter an optional profile name
func (h *TOTPSetupHandler) promptForProfile() (string, error) {
	fmt.Print("Enter profile name (optional, for multiple accounts with the same service): ")
	profile, _ := h.reader.ReadString('\n')
	profile = strings.TrimSpace(profile)
	return profile, nil
}

// promptForCaptureMethod prompts the user to choose how to capture the TOTP secret
func (h *TOTPSetupHandler) promptForCaptureMethod() (string, error) {
	fmt.Println()
	fmt.Println("How would you like to capture the TOTP secret?")
	fmt.Println("1: Enter the secret key manually")
	fmt.Println("2: Capture QR code from screen")
	fmt.Print("Enter your choice (1-2): ")
	choice, _ := h.reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	if choice != "1" && choice != "2" {
		return "", fmt.Errorf("invalid choice, please select 1 or 2")
	}

	return choice, nil
}

// captureTOTPSecret captures the TOTP secret using the specified method
func (h *TOTPSetupHandler) captureTOTPSecret(choice string) (string, error) {
	var secretStr string

	switch choice {
	case "1": // Manual entry
		fmt.Println("Enter your TOTP secret key (this will not be echoed):")
		secret, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return "", fmt.Errorf("failed to read secret: %w", err)
		}
		fmt.Println() // Add a newline after the hidden input

		// Handle secret securely
		secretBytes := secret
		defer secure.SecureZeroBytes(secretBytes)
		secretStr = strings.TrimSpace(string(secretBytes))

	case "2": // QR code capture
		fmt.Println("When ready, press Enter to activate screenshot mode")
		fmt.Print("Press Enter to continue...")
		h.reader.ReadString('\n')

		var err error
		secretStr, err = qrcode.ScanQRCode()
		if err != nil {
			return "", fmt.Errorf("failed to process QR code: %w", err)
		}
		fmt.Println("✅ QR code successfully captured and decoded!")

	default:
		return "", fmt.Errorf("invalid choice, please select 1 or 2")
	}

	return secretStr, nil
}

// showTOTPSetupCompletionMessage displays the final success message with usage instructions
func (h *TOTPSetupHandler) showTOTPSetupCompletionMessage(serviceName, profile string) {
	fmt.Printf("✅ Setup complete! You can now use 'sesh --service totp --service-name %s", serviceName)
	if profile != "" {
		fmt.Printf(" --profile %s", profile)
	}
	fmt.Println("' to generate TOTP codes.")
	fmt.Printf("Use 'sesh --service totp --service-name %s --clip' to copy the code to clipboard.\n", serviceName)
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

	choice, err := h.promptForCaptureMethod()
	if err != nil {
		return err
	}

	secretStr, err := h.captureTOTPSecret(choice)
	if err != nil {
		return err
	}

	switch choice {
	case "1":
		// Manual entry
		fmt.Println("Enter your TOTP secret key (this will not be echoed):")
		secret, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return fmt.Errorf("failed to read secret")
		}
		fmt.Println() // Add a newline after the hidden input

		secretStr = string(secret)
		secretStr = strings.TrimSpace(secretStr)

	case "2":
		// QR code capture flow
		fmt.Println("When ready, press Enter to activate screenshot mode")
		fmt.Print("Press Enter to continue...")
		h.reader.ReadString('\n')

		// Capture and process the QR code
		secretStr, err = qrcode.ScanQRCode()
		if err != nil {
			return fmt.Errorf("failed to process QR code: %v", err)
		}
		fmt.Println("✅ QR code successfully captured and decoded!")

	default:
		return fmt.Errorf("invalid choice, please select 1 or 2")
	}

	// Validate and normalize the TOTP secret
	normalizedSecret, err := totp.ValidateAndNormalizeSecret(secretStr)
	if err != nil {
		return fmt.Errorf("invalid TOTP secret: %w", err)
	}
	secretStr = normalizedSecret

	// Generate two consecutive TOTP codes
	firstCode, secondCode, err := totp.GenerateConsecutiveCodes(secretStr)
	if err != nil {
		return fmt.Errorf("failed to generate TOTP codes: %s", err)
	}

	// Store in keychain using the provider
	user, err := env.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("failed to get current user: %w", err)
	}

	// Build service key using consistent helper pattern
	serviceKey := h.createTOTPServiceName(serviceName, profile)

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

	fmt.Printf("✅ Setup complete! You can now use 'sesh --service totp --service-name %s", serviceName)
	if profile != "" {
		fmt.Printf(" --profile %s", profile)
	}
	fmt.Println("' to generate TOTP codes.")
	fmt.Println("Use 'sesh --service totp --service-name " + serviceName + " --clip' to copy the code to clipboard.")

	return nil
}

// This function is deprecated and will be removed in a future version
func setupGenericTOTP() {
	reader := bufio.NewReader(os.Stdin)

	// Ask for service name
	fmt.Print("Enter name for this TOTP service: ")
	serviceName, _ := reader.ReadString('\n')
	serviceName = strings.TrimSpace(serviceName)

	if serviceName == "" {
		fmt.Println("❌ Service name cannot be empty")
		os.Exit(1)
	}

	// Ask for profile name (for multiple accounts with the same service)
	fmt.Print("Enter profile name (optional, for multiple accounts with the same service): ")
	profile, _ := reader.ReadString('\n')
	profile = strings.TrimSpace(profile)

	// Ask user how they want to capture the TOTP secret
	fmt.Println()
	fmt.Println("How would you like to capture the TOTP secret?")
	fmt.Println("1: Enter the secret key manually")
	fmt.Println("2: Capture QR code from screen")
	fmt.Print("Enter your choice (1-2): ")
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	// Variable to store the secret
	var secretStr string
	var err error

	switch choice {
	case "1":
		// Manual entry (original flow)
		fmt.Println("Enter your TOTP secret key (this will not be echoed):")
		secret, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			fmt.Println("❌ Failed to read secret")
			os.Exit(1)
		}
		fmt.Println() // Add a newline after the hidden input

		// Generate two consecutive TOTP codes to help with setup
		secretStr = string(secret)
		secretStr = strings.TrimSpace(secretStr)

	case "2":
		// QR code capture flow
		fmt.Println("When ready, press Enter to activate screenshot mode")
		fmt.Print("Press Enter to continue...")
		reader.ReadString('\n')

		// Capture and process the QR code
		secretStr, err = qrcode.ScanQRCode()
		if err != nil {
			fmt.Printf("❌ Failed to process QR code: %v\n", err)
			fmt.Println("Please try again with manual entry or restart the setup.")
			os.Exit(1)
		}
		fmt.Println("✅ QR code successfully captured and decoded!")

	default:
		fmt.Println("❌ Invalid choice. Please run setup again and select 1 or 2.")
		os.Exit(1)
	}

	// Validate secret key format (basic check)
	if len(secretStr) < 16 {
		fmt.Println("❌ Secret key seems too short. Please double-check and try again.")
		os.Exit(1)
	}

	// Generate two consecutive TOTP codes
	firstCode, secondCode, err := totp.GenerateConsecutiveCodes(secretStr)
	if err != nil {
		fmt.Printf("❌ Failed to generate TOTP codes: %s\n", err)
		os.Exit(1)
	}

	// Store in keychain
	user, err := env.GetCurrentUser()
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ %s\n", err)
		os.Exit(1)
	}

	// Use our fixed binary path for consistent keychain access
	execPath := constants.GetSeshBinaryPath()
	if execPath == "" {
		fmt.Println("❌ Could not determine the path to the sesh binary, cannot access keychain")
		os.Exit(1)
	}

	// Build service key
	var serviceKey string
	if profile == "" {
		serviceKey = fmt.Sprintf("sesh-totp-%s", serviceName)
	} else {
		serviceKey = fmt.Sprintf("sesh-totp-%s-%s", serviceName, profile)
	}

	// Use security command to store secret with -T flag to restrict access
	addCmd := exec.Command("security", "add-generic-password",
		"-a", user,
		"-s", serviceKey,
		"-w", secretStr,
		"-U",           // Update if exists
		"-T", execPath, // Only allow the sesh binary to access this item
	)

	err = addCmd.Run()
	if err != nil {
		fmt.Println("❌ Failed to store secret in keychain")
		os.Exit(1)
	}

	// Store metadata for better organization and retrieval
	description := fmt.Sprintf("TOTP for %s", serviceName)
	if profile != "" {
		description = fmt.Sprintf("TOTP for %s profile %s", serviceName, profile)
	}

	// Store metadata - CRITICAL for entry retrieval
	err = keychain.StoreEntryMetadata(constants.TOTPServicePrefix, serviceKey, user, description)
	if err != nil {
		fmt.Println("❌ Failed to store metadata for entry retrieval")
		fmt.Println("⚠️ This entry might not appear when listing available TOTP services")
		fmt.Println("⚠️ You might need to create the entry again or check keychain permissions")
		os.Exit(1)
	}

	// Display the generated TOTP codes for setup verification
	fmt.Println("✅ Generated TOTP codes for verification:")
	fmt.Printf("   Current code: %s\n", firstCode)
	fmt.Printf("   Next code: %s\n", secondCode)
	fmt.Println("   (Use these codes if your service requires verification during setup)")
	fmt.Println()

	fmt.Printf("✅ Setup complete! You can now use 'sesh --service totp --service-name %s", serviceName)
	if profile != "" {
		fmt.Printf(" --profile %s", profile)
	}
	fmt.Println("' to generate TOTP codes.")
	fmt.Println("Use 'sesh --service totp --service-name " + serviceName + " --clip' to copy the code to clipboard.")
}
