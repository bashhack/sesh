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
}

// NewAWSSetupHandler creates a new AWS setup handler
func NewAWSSetupHandler(provider keychain.Provider) *AWSSetupHandler {
	return &AWSSetupHandler{
		keychainProvider: provider,
	}
}

// ServiceName returns the name of the service
func (h *AWSSetupHandler) ServiceName() string {
	return "aws"
}

// Setup performs the AWS setup
func (h *AWSSetupHandler) Setup() error {
	fmt.Println("🔐 Setting up AWS credentials...")
	reader := bufio.NewReader(os.Stdin)

	_, err := exec.LookPath("aws")
	if err != nil {
		return fmt.Errorf("AWS CLI not found. Please install it first: https://aws.amazon.com/cli/")
	}

	fmt.Println("✅ AWS CLI is installed")

	fmt.Print("Enter AWS CLI profile name (leave empty for default): ")
	profile, _ := reader.ReadString('\n')
	profile = strings.TrimSpace(profile)

	var userArn string
	var cmd *exec.Cmd

	if profile == "" {
		cmd = exec.Command("aws", "sts", "get-caller-identity", "--query", "Arn", "--output", "text")
	} else {
		cmd = exec.Command("aws", "sts", "get-caller-identity", "--profile", profile, "--query", "Arn", "--output", "text")
	}

	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get AWS identity. Make sure your AWS credentials are configured")
	}

	userArn = strings.TrimSpace(string(output))
	fmt.Printf("✅ Found AWS identity: %s\n", userArn)

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
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

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
			return fmt.Errorf("failed to read secret")
		}
		fmt.Println() // Add a newline after the hidden input

		secretStr = string(secret)
		secretStr = strings.TrimSpace(secretStr)

	case "2": // QR code capture flow
		fmt.Println(`
5. Keep the QR code visible on your screen
6. When ready, press Enter to activate screenshot mode

❗ DO NOT COMPLETE THE AWS SETUP YET - we'll do that together

Press Enter when you're ready to capture the QR code...`)
		reader.ReadString('\n')

		fmt.Println("📸 Position your cursor at the top-left of the QR code, then click and drag to the bottom-right")
		var err error
		secretStr, err = qrcode.ScanQRCode()
		if err != nil {
			return fmt.Errorf("failed to process QR code: %v", err)
		}
		fmt.Println("✅ QR code successfully captured and decoded!")

	default:
		return fmt.Errorf("invalid choice, please select 1 or 2")
	}

	if len(secretStr) < 16 {
		// Validate secret key format (basic check)
		return fmt.Errorf("secret key seems too short, please double-check and try again")
	}

	// At the time of writing, AWS requires two codes during setup
	firstCode, secondCode, err := totp.GenerateConsecutiveCodes(secretStr)
	if err != nil {
		return fmt.Errorf("failed to generate TOTP codes: %s", err)
	}

	fmt.Printf(`✅ Generated TOTP codes for AWS setup
First code: %s
Second code: %s

IMPORTANT - FOLLOW THESE STEPS:
1. Enter these codes in the AWS Console
2. Click the "Add MFA" button to complete setup
3. Wait for confirmation in the AWS console that setup is complete

Press Enter ONLY AFTER you see "MFA device was successfully assigned" in AWS console...`, firstCode, secondCode)
	reader.ReadString('\n')

	var mfaCmd *exec.Cmd
	if profile == "" {
		mfaCmd = exec.Command("aws", "iam", "list-mfa-devices", "--query", "MFADevices[].SerialNumber", "--output", "text")
	} else {
		mfaCmd = exec.Command("aws", "iam", "list-mfa-devices", "--profile", profile, "--query", "MFADevices[].SerialNumber", "--output", "text")
	}

	mfaOutput, err := mfaCmd.Output()
	var mfaArn string

	// Try to fetch MFA devices, with retries if none are found
	maxRetries := 2
	retryCount := 0
	
	mfaDeviceLoop: for {
		if err == nil && len(strings.TrimSpace(string(mfaOutput))) > 0 {
			// MFA devices were found, process them
			mfaDevices := strings.Split(strings.TrimSpace(string(mfaOutput)), "\t")
			
			// Always show the list of devices and let the user choose, even if there's only one
			// This handles cases where they already had an MFA device and the new one isn't
			// showing up yet, or they had a single existing device that isn't the one they just created
			fmt.Println("\nFound MFA device(s):")
			for i, device := range mfaDevices {
				fmt.Printf("%d: %s\n", i+1, device)
			}
			
			selectionPrompt:
			fmt.Print("\nChoose the MFA device you just created (1-" + fmt.Sprintf("%d", len(mfaDevices)) + 
				"), 'r' to refresh the list, or 'm' to enter manually: ")
			choice, _ := reader.ReadString('\n')
			choice = strings.TrimSpace(choice)
			
			// Handle special options
			switch choice {
			case "r", "R":
				// Refresh MFA devices list
				fmt.Println("\n🔄 Refreshing MFA device list...")
				if profile == "" {
					mfaCmd = exec.Command("aws", "iam", "list-mfa-devices", "--query", "MFADevices[].SerialNumber", "--output", "text")
				} else {
					mfaCmd = exec.Command("aws", "iam", "list-mfa-devices", "--profile", profile, "--query", "MFADevices[].SerialNumber", "--output", "text")
				}
				
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
				// Manual entry
				fmt.Print("Enter your MFA ARN (format: arn:aws:iam::ACCOUNT_ID:mfa/USERNAME): ")
				mfaArn, _ = reader.ReadString('\n')
				mfaArn = strings.TrimSpace(mfaArn)
				deviceFound = true
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
				deviceFound = true
				break mfaDeviceLoop // Exit the entire for loop with our selected device
			}
		}

		// No MFA devices found or error occurred
		if retryCount >= maxRetries {
			// We've exhausted our retries, fall back to manual entry
			fmt.Println("\n❗ No MFA devices found after multiple attempts. You'll need to provide your MFA ARN manually.")
			fmt.Print("Enter your MFA ARN (format: arn:aws:iam::ACCOUNT_ID:mfa/USERNAME): ")
			mfaArn, _ = reader.ReadString('\n')
			mfaArn = strings.TrimSpace(mfaArn)
			deviceFound = true // Set deviceFound to true for manual entry
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

		retryChoice, _ := reader.ReadString('\n')
		retryChoice = strings.TrimSpace(retryChoice)

		switch retryChoice {
		case "1": // Wait and retry
			fmt.Println("\n⏳ Waiting 5 seconds for AWS to register your MFA device...")
			time.Sleep(5 * time.Second)

			// Try fetching the MFA device again
			if profile == "" {
				mfaCmd = exec.Command("aws", "iam", "list-mfa-devices", "--query", "MFADevices[].SerialNumber", "--output", "text")
			} else {
				mfaCmd = exec.Command("aws", "iam", "list-mfa-devices", "--profile", profile, "--query", "MFADevices[].SerialNumber", "--output", "text")
			}

			mfaOutput, err = mfaCmd.Output()
			retryCount++

		case "2": // Return to console
			fmt.Println(`
Please complete these steps in the AWS Console:
1. Make sure you've clicked "Add MFA" after entering the TOTP codes
2. Confirm you see "MFA device was successfully assigned" message
3. Press Enter when complete...`)
			reader.ReadString('\n')

			// Try fetching again
			if profile == "" {
				mfaCmd = exec.Command("aws", "iam", "list-mfa-devices", "--query", "MFADevices[].SerialNumber", "--output", "text")
			} else {
				mfaCmd = exec.Command("aws", "iam", "list-mfa-devices", "--profile", profile, "--query", "MFADevices[].SerialNumber", "--output", "text")
			}

			mfaOutput, err = mfaCmd.Output()
			retryCount++

		case "3": // Manual entry 
			fmt.Print("Enter your MFA ARN (format: arn:aws:iam::ACCOUNT_ID:mfa/USERNAME): ")
			mfaArn, _ = reader.ReadString('\n')
			mfaArn = strings.TrimSpace(mfaArn)
			deviceFound = true // Set deviceFound to true
			break mfaDeviceLoop // Exit the loop completely
			
		default: // Invalid input
			fmt.Println("\n❌ Invalid choice. Please select 1, 2, or 3.")
			// Stay in the loop and show the options again
		}
	}

	user, err := env.GetCurrentUser()
	if err != nil {
		return fmt.Errorf("failed to get current user: %w", err)
	}

	var serviceName string
	if profile == "" {
		// For the default profile, use "default" as the profile name
		serviceName = fmt.Sprintf("%s-default", constants.AWSServicePrefix)
	} else {
		serviceName = fmt.Sprintf("%s-%s", constants.AWSServicePrefix, profile)
	}

	err = h.keychainProvider.SetSecret(user, serviceName, secretStr)
	if err != nil {
		return fmt.Errorf("failed to store secret in keychain: %w", err)
	}

	var serialServiceName string
	if profile == "" {
		// For the default profile, use "default" as the profile name
		serialServiceName = fmt.Sprintf("%s-default", constants.AWSServiceMFAPrefix)
	} else {
		serialServiceName = fmt.Sprintf("%s-%s", constants.AWSServiceMFAPrefix, profile)
	}

	err = h.keychainProvider.SetSecret(user, serialServiceName, mfaArn)
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

	fmt.Println(`
✅ Setup complete! You can now use 'sesh' to generate AWS temporary credentials.

🚀 Next steps:
1. Run 'sesh -service aws' to generate a temporary session token
2. The credentials will be automatically exported to your shell
3. You can now use AWS CLI commands with MFA security`)

	if profile == "" {
		fmt.Println(`
To use this setup, run without the --profile flag:
(The default AWS profile will be used)`)
	} else {
		fmt.Printf("\nTo use this setup, run: sesh --profile %s\n", profile)
	}

	return nil
}

// TOTP Setup Handler

// TOTPSetupHandler implements SetupHandler for TOTP
type TOTPSetupHandler struct {
	keychainProvider keychain.Provider
}

// NewTOTPSetupHandler creates a new TOTP setup handler
func NewTOTPSetupHandler(provider keychain.Provider) *TOTPSetupHandler {
	return &TOTPSetupHandler{
		keychainProvider: provider,
	}
}

// ServiceName returns the name of the service
func (h *TOTPSetupHandler) ServiceName() string {
	return "totp"
}

// Setup performs the TOTP setup
func (h *TOTPSetupHandler) Setup() error {
	fmt.Println("🔐 Setting up TOTP credentials...")
	reader := bufio.NewReader(os.Stdin)

	// Ask for service name
	fmt.Print("Enter name for this TOTP service: ")
	serviceName, _ := reader.ReadString('\n')
	serviceName = strings.TrimSpace(serviceName)

	if serviceName == "" {
		return fmt.Errorf("service name cannot be empty")
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
		reader.ReadString('\n')

		// Capture and process the QR code
		secretStr, err = qrcode.ScanQRCode()
		if err != nil {
			return fmt.Errorf("failed to process QR code: %v", err)
		}
		fmt.Println("✅ QR code successfully captured and decoded!")

	default:
		return fmt.Errorf("invalid choice, please select 1 or 2")
	}

	// Validate secret key format (basic check)
	if len(secretStr) < 16 {
		return fmt.Errorf("secret key seems too short, please double-check and try again")
	}

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

	// Build service key
	var serviceKey string
	if profile == "" {
		serviceKey = fmt.Sprintf("sesh-totp-%s", serviceName)
	} else {
		serviceKey = fmt.Sprintf("sesh-totp-%s-%s", serviceName, profile)
	}

	// Store the secret using the keychain provider
	err = h.keychainProvider.SetSecret(user, serviceKey, secretStr)
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

// setupAWS configures AWS-specific setup
//func setupAWS() {
//	//reader := bufio.NewReader(os.Stdin)
//
//	// Check if AWS CLI is installed
//	//_, err := exec.LookPath("aws")
//	//if err != nil {
//	//	fmt.Println("❌ AWS CLI not found. Please install it first: https://aws.amazon.com/cli/")
//	//	os.Exit(1)
//	//}
//
//	//fmt.Println("✅ AWS CLI is installed")
//
//	// Ask for AWS profile
//	//fmt.Print("Enter AWS CLI profile name (leave empty for default): ")
//	//profile, _ := reader.ReadString('\n')
//	//profile = strings.TrimSpace(profile)
//
//	// Try to get current user's AWS ARN
//	//var userArn string
//	//var cmd *exec.Cmd
//
//	//if profile == "" {
//	//	cmd = exec.Command("aws", "sts", "get-caller-identity", "--query", "Arn", "--output", "text")
//	//} else {
//	//	cmd = exec.Command("aws", "sts", "get-caller-identity", "--profile", profile, "--query", "Arn", "--output", "text")
//	//}
//
//	//output, err := cmd.Output()
//	//if err != nil {
//	//	fmt.Println("❌ Failed to get AWS identity. Make sure your AWS credentials are configured.")
//	//	fmt.Println("Run 'aws configure' first, then try again.")
//	//	os.Exit(1)
//	//}
//
//	//userArn = strings.TrimSpace(string(output))
//	//fmt.Printf("✅ Found AWS identity: %s\n", userArn)
//
//	// Guide user through creating a virtual MFA device
//	//fmt.Println("📱 Let's set up a virtual MFA device for your AWS account")
//	//fmt.Println("1. Log in to the AWS Console at https://console.aws.amazon.com")
//	//fmt.Println("2. Navigate to IAM → Users → Your Username → Security credentials")
//	//fmt.Println("3. Under 'Multi-factor authentication (MFA)', click 'Assign MFA device'")
//	//fmt.Println("4. Choose 'Virtual MFA device' and click 'Continue'")
//
//	// Ask user how they want to capture the MFA secret
//	//fmt.Println()
//	//fmt.Println("How would you like to capture the MFA secret?")
//	//fmt.Println("1: Enter the secret key manually (click 'Show secret key' in AWS)")
//	//fmt.Println("2: Capture QR code from screen (take a screenshot of the QR code)")
//	//fmt.Print("Enter your choice (1-2): ")
//	//choice, _ := reader.ReadString('\n')
//	//choice = strings.TrimSpace(choice)
//
//	// Variable to store the secret
//	//var secretStr string
//
//	//switch choice {
//	//case "1":
//	//	// Manual entry (original flow)
//	//	fmt.Println("5. On the 'Set up virtual MFA device' screen, DO NOT scan the QR code")
//	//	fmt.Println("6. Click 'Show secret key' and copy the secret key")
//	//	fmt.Println()
//	//	fmt.Println("❗ DO NOT COMPLETE THE AWS SETUP YET - we'll do that together")
//	//	fmt.Println()
//	//
//	//	// Get MFA secret
//	//	fmt.Print("Paste the secret key here (this will not be echoed): ")
//	//	secret, err := term.ReadPassword(int(syscall.Stdin))
//	//	if err != nil {
//	//		fmt.Println("❌ Failed to read secret")
//	//		os.Exit(1)
//	//	}
//	//	fmt.Println() // Add a newline after the hidden input
//	//
//	//	secretStr = string(secret)
//	//	secretStr = strings.TrimSpace(secretStr)
//	//
//	//case "2":
//	//	// QR code capture flow
//	//	fmt.Println("5. Keep the QR code visible on your screen")
//	//	fmt.Println("6. When ready, press Enter to activate screenshot mode")
//	//	fmt.Println()
//	//	fmt.Println("❗ DO NOT COMPLETE THE AWS SETUP YET - we'll do that together")
//	//	fmt.Println()
//	//	fmt.Print("Press Enter when you're ready to capture the QR code...")
//	//	reader.ReadString('\n')
//	//
//	//	// Take the screenshot
//	//	fmt.Println("📸 Position your cursor at the top-left of the QR code, then click and drag to the bottom-right")
//	//	var err error
//	//	secretStr, err = qrcode.ScanQRCode()
//	//	if err != nil {
//	//		fmt.Printf("❌ Failed to process QR code: %v\n", err)
//	//		fmt.Println("Please try again with manual entry or restart the setup.")
//	//		os.Exit(1)
//	//	}
//	//	fmt.Println("✅ QR code successfully captured and decoded!")
//	//
//	//default:
//	//	fmt.Println("❌ Invalid choice. Please run setup again and select 1 or 2.")
//	//	os.Exit(1)
//	//}
//
//	// Validate secret key format (basic check)
//	//if len(secretStr) < 16 {
//	//	fmt.Println("❌ Secret key seems too short. Please double-check and try again.")
//	//	os.Exit(1)
//	//}
//
//	// Generate two consecutive TOTP codes for AWS verification
//	//firstCode, secondCode, err := totp.GenerateConsecutiveCodes(secretStr)
//	//if err != nil {
//	//	fmt.Printf("❌ Failed to generate TOTP codes: %s\n", err)
//	//	os.Exit(1)
//	//}
//
//	//fmt.Println("✅ Generated TOTP codes for AWS setup")
//	//fmt.Printf("   First code: %s\n", firstCode)
//	//fmt.Printf("   Second code: %s\n", secondCode)
//	//fmt.Println()
//	//fmt.Println("Enter these codes in the AWS Console and complete the MFA setup")
//	//fmt.Println("Press Enter once you've completed the setup...")
//	//reader.ReadString('\n')
//
//	// Get the MFA ARN after setup is complete
//	//var mfaCmd *exec.Cmd
//	//if profile == "" {
//	//	mfaCmd = exec.Command("aws", "iam", "list-mfa-devices", "--query", "MFADevices[].SerialNumber", "--output", "text")
//	//} else {
//	//	mfaCmd = exec.Command("aws", "iam", "list-mfa-devices", "--profile", profile, "--query", "MFADevices[].SerialNumber", "--output", "text")
//	//}
//
//	//mfaOutput, err := mfaCmd.Output()
//	//var mfaArn string
//
//	//if err != nil || len(strings.TrimSpace(string(mfaOutput))) == 0 {
//	//	fmt.Println("❓ No MFA devices found. You'll need to provide your MFA ARN manually.")
//	//	fmt.Print("Enter your MFA ARN (format: arn:aws:iam::ACCOUNT_ID:mfa/USERNAME): ")
//	//	mfaArn, _ = reader.ReadString('\n')
//	//	mfaArn = strings.TrimSpace(mfaArn)
//	//} else {
//	//	// If there are multiple MFA devices, list them and ask the user to choose
//	//	mfaDevices := strings.Split(strings.TrimSpace(string(mfaOutput)), "\t")
//	//	if len(mfaDevices) == 1 {
//	//		mfaArn = mfaDevices[0]
//	//		fmt.Printf("✅ Found MFA device: %s\n", mfaArn)
//	//	} else {
//	//		fmt.Println("Found multiple MFA devices:")
//	//		for i, device := range mfaDevices {
//	//			fmt.Printf("%d: %s\n", i+1, device)
//	//		}
//	//		fmt.Print("Choose the MFA device you just created (1-n): ")
//	//		choice, _ := reader.ReadString('\n')
//	//		choice = strings.TrimSpace(choice)
//	//		var index int
//	//		fmt.Sscanf(choice, "%d", &index)
//	//		if index < 1 || index > len(mfaDevices) {
//	//			fmt.Println("❌ Invalid choice")
//	//			os.Exit(1)
//	//		}
//	//		mfaArn = mfaDevices[index-1]
//	//		fmt.Printf("✅ Selected MFA device: %s\n", mfaArn)
//	//	}
//	//}
//
//	// Store in keychain
//	//user, err := env.GetCurrentUser()
//	//if err != nil {
//	//	fmt.Fprintf(os.Stderr, "❌ %s\n", err)
//	//	os.Exit(1)
//	//}
//
//	// Use the profile name for the keychain service name
//	//var serviceName string
//	//if profile == "" {
//	//	// For default profile, use "default" as the profile name
//	//	serviceName = fmt.Sprintf("%s-default", constants.AWSServicePrefix)
//	//} else {
//	//	serviceName = fmt.Sprintf("%s-%s", constants.AWSServicePrefix, profile)
//	//}
//
//	// Use our fixed binary path for consistent keychain access
//	//execPath := constants.GetSeshBinaryPath()
//	//if execPath == "" {
//	//	fmt.Println("❌ Could not determine the path to the sesh binary, cannot access keychain")
//	//	os.Exit(1)
//	//}
//
//	// Use security command to store secret with -T flag to restrict access
//	//addCmd := exec.Command("security", "add-generic-password",
//	//	"-a", user,
//	//	"-s", serviceName,
//	//	"-w", secretStr,
//	//	"-U",           // Update if exists
//	//	"-T", execPath, // Only allow the sesh binary to access this item
//	//)
//	//err = addCmd.Run()
//	//if err != nil {
//	//	fmt.Println("❌ Failed to store secret in keychain")
//	//	os.Exit(1)
//	//}
//
//	// Also store the MFA serial ARN
//	//var serialServiceName string
//	//if profile == "" {
//	//	// For default profile, use "default" as the profile name
//	//	serialServiceName = fmt.Sprintf("%s-default", constants.AWSServiceMFAPrefix)
//	//} else {
//	//	serialServiceName = fmt.Sprintf("%s-%s", constants.AWSServiceMFAPrefix, profile)
//	//}
//	//addSerialCmd := exec.Command("security", "add-generic-password",
//	//	"-a", user,
//	//	"-s", serialServiceName,
//	//	"-w", mfaArn,
//	//	"-U",           // Update if exists
//	//	"-T", execPath, // Only allow the sesh binary to access this item
//	//)
//	//err = addSerialCmd.Run()
//	//if err != nil {
//	//	fmt.Println("❌ Failed to store MFA serial in keychain")
//	//	os.Exit(1)
//	//}
//
//	// Store metadata for better organization and retrieval
//	//description := "AWS MFA"
//	//if profile != "" {
//	//	description = fmt.Sprintf("AWS MFA for profile %s", profile)
//	//}
//
//	// Store metadata - CRITICAL for entry retrieval
//	//err = keychain.StoreEntryMetadata(constants.AWSServicePrefix, serviceName, user, description)
//	//if err != nil {
//	//	fmt.Println("❌ Failed to store metadata for entry retrieval")
//	//	fmt.Println("⚠️ This entry might not appear when listing available AWS profiles")
//	//	fmt.Println("⚠️ You might need to create the entry again or check keychain permissions")
//	//	os.Exit(1)
//	//}
//
//	//fmt.Println("\n✅ Setup complete! You can now use 'sesh' to generate AWS temporary credentials.")
//	//fmt.Println()
//	//fmt.Println("🚀 Next steps:")
//	//fmt.Println("1. Run 'sesh' to generate a temporary session token")
//	//fmt.Println("2. The credentials will be automatically exported to your shell")
//	//fmt.Println("3. You can now use AWS CLI commands with MFA security")
//	//
//	//if profile == "" {
//	//	fmt.Println("\nTo use this setup, run: sesh")
//	//	fmt.Println("(The default AWS profile will be used)")
//	//} else {
//	//	fmt.Printf("\nTo use this setup, run: sesh --profile %s\n", profile)
//	//}
//}

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
