package setup

import (
	"bufio"
	"fmt"
	"github.com/bashhack/sesh/internal/constants"
	"github.com/bashhack/sesh/internal/keychain"
	"github.com/bashhack/sesh/internal/qrcode"
	"github.com/bashhack/sesh/internal/totp"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/bashhack/sesh/internal/env"
	"golang.org/x/term"
)

// GetSeshBinaryPath returns the fixed sesh binary path used for keychain access
func GetSeshBinaryPath() string {
	// Use a fixed path for security consistency
	// Use the same path that's defined in keychain.go
	return os.ExpandEnv("$HOME/.local/bin/sesh")
}

// Variables to allow testing

var RunWizard = runWizard
var RunWizardForService = runWizardForService

// runWizard runs the setup wizard, maintaining backward compatibility
func runWizard() {
	RunWizardForService("aws")
}

// runWizardForService runs the setup wizard for a specific service
func runWizardForService(serviceName string) {
	fmt.Println("🔐 Setting up sesh...")

	switch serviceName {
	case "aws":
		setupAWS()
	case "totp":
		setupGenericTOTP()
	default:
		fmt.Printf("Unknown service: %s\n", serviceName)
		os.Exit(1)
	}
}

// setupAWS configures AWS-specific setup
func setupAWS() {
	reader := bufio.NewReader(os.Stdin)

	// Check if AWS CLI is installed
	_, err := exec.LookPath("aws")
	if err != nil {
		fmt.Println("❌ AWS CLI not found. Please install it first: https://aws.amazon.com/cli/")
		os.Exit(1)
	}

	fmt.Println("✅ AWS CLI is installed")

	// Ask for AWS profile
	fmt.Print("Enter AWS CLI profile name (leave empty for default): ")
	profile, _ := reader.ReadString('\n')
	profile = strings.TrimSpace(profile)

	// Try to get current user's AWS ARN
	var userArn string
	var cmd *exec.Cmd

	if profile == "" {
		cmd = exec.Command("aws", "sts", "get-caller-identity", "--query", "Arn", "--output", "text")
	} else {
		cmd = exec.Command("aws", "sts", "get-caller-identity", "--profile", profile, "--query", "Arn", "--output", "text")
	}

	output, err := cmd.Output()
	if err != nil {
		fmt.Println("❌ Failed to get AWS identity. Make sure your AWS credentials are configured.")
		fmt.Println("Run 'aws configure' first, then try again.")
		os.Exit(1)
	}

	userArn = strings.TrimSpace(string(output))
	fmt.Printf("✅ Found AWS identity: %s\n", userArn)

	// Guide user through creating a virtual MFA device
	fmt.Println("📱 Let's set up a virtual MFA device for your AWS account")
	fmt.Println("1. Log in to the AWS Console at https://console.aws.amazon.com")
	fmt.Println("2. Navigate to IAM → Users → Your Username → Security credentials")
	fmt.Println("3. Under 'Multi-factor authentication (MFA)', click 'Assign MFA device'")
	fmt.Println("4. Choose 'Virtual MFA device' and click 'Continue'")

	// Ask user how they want to capture the MFA secret
	fmt.Println()
	fmt.Println("How would you like to capture the MFA secret?")
	fmt.Println("1: Enter the secret key manually (click 'Show secret key' in AWS)")
	fmt.Println("2: Capture QR code from screen (take a screenshot of the QR code)")
	fmt.Print("Enter your choice (1-2): ")
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	// Variable to store the secret
	var secretStr string

	switch choice {
	case "1":
		// Manual entry (original flow)
		fmt.Println("5. On the 'Set up virtual MFA device' screen, DO NOT scan the QR code")
		fmt.Println("6. Click 'Show secret key' and copy the secret key")
		fmt.Println()
		fmt.Println("❗ DO NOT COMPLETE THE AWS SETUP YET - we'll do that together")
		fmt.Println()

		// Get MFA secret
		fmt.Print("Paste the secret key here (this will not be echoed): ")
		secret, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			fmt.Println("❌ Failed to read secret")
			os.Exit(1)
		}
		fmt.Println() // Add a newline after the hidden input

		secretStr = string(secret)
		secretStr = strings.TrimSpace(secretStr)

	case "2":
		// QR code capture flow
		fmt.Println("5. Keep the QR code visible on your screen")
		fmt.Println("6. When ready, press Enter to activate screenshot mode")
		fmt.Println()
		fmt.Println("❗ DO NOT COMPLETE THE AWS SETUP YET - we'll do that together")
		fmt.Println()
		fmt.Print("Press Enter when you're ready to capture the QR code...")
		reader.ReadString('\n')

		// Take the screenshot
		fmt.Println("📸 Position your cursor at the top-left of the QR code, then click and drag to the bottom-right")
		var err error
		secretStr, err = captureAndProcessQRCode()
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

	// Generate two consecutive TOTP codes for AWS verification
	firstCode, secondCode, err := totp.GenerateConsecutiveCodes(secretStr)
	if err != nil {
		fmt.Printf("❌ Failed to generate TOTP codes: %s\n", err)
		os.Exit(1)
	}

	fmt.Println("✅ Generated TOTP codes for AWS setup")
	fmt.Printf("   First code: %s\n", firstCode)
	fmt.Printf("   Second code: %s\n", secondCode)
	fmt.Println()
	fmt.Println("Enter these codes in the AWS Console and complete the MFA setup")
	fmt.Println("Press Enter once you've completed the setup...")
	reader.ReadString('\n')

	// Get the MFA ARN after setup is complete
	var mfaCmd *exec.Cmd
	if profile == "" {
		mfaCmd = exec.Command("aws", "iam", "list-mfa-devices", "--query", "MFADevices[].SerialNumber", "--output", "text")
	} else {
		mfaCmd = exec.Command("aws", "iam", "list-mfa-devices", "--profile", profile, "--query", "MFADevices[].SerialNumber", "--output", "text")
	}

	mfaOutput, err := mfaCmd.Output()
	var mfaArn string

	if err != nil || len(strings.TrimSpace(string(mfaOutput))) == 0 {
		fmt.Println("❓ No MFA devices found. You'll need to provide your MFA ARN manually.")
		fmt.Print("Enter your MFA ARN (format: arn:aws:iam::ACCOUNT_ID:mfa/USERNAME): ")
		mfaArn, _ = reader.ReadString('\n')
		mfaArn = strings.TrimSpace(mfaArn)
	} else {
		// If there are multiple MFA devices, list them and ask the user to choose
		mfaDevices := strings.Split(strings.TrimSpace(string(mfaOutput)), "\t")
		if len(mfaDevices) == 1 {
			mfaArn = mfaDevices[0]
			fmt.Printf("✅ Found MFA device: %s\n", mfaArn)
		} else {
			fmt.Println("Found multiple MFA devices:")
			for i, device := range mfaDevices {
				fmt.Printf("%d: %s\n", i+1, device)
			}
			fmt.Print("Choose the MFA device you just created (1-n): ")
			choice, _ := reader.ReadString('\n')
			choice = strings.TrimSpace(choice)
			var index int
			fmt.Sscanf(choice, "%d", &index)
			if index < 1 || index > len(mfaDevices) {
				fmt.Println("❌ Invalid choice")
				os.Exit(1)
			}
			mfaArn = mfaDevices[index-1]
			fmt.Printf("✅ Selected MFA device: %s\n", mfaArn)
		}
	}

	// Store in keychain
	user, err := env.GetCurrentUser()
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ %s\n", err)
		os.Exit(1)
	}

	// Use the profile name for the keychain service name
	var serviceName string
	if profile == "" {
		// For default profile, use "default" as the profile name
		serviceName = fmt.Sprintf("%s-default", constants.AWSServicePrefix)
	} else {
		serviceName = fmt.Sprintf("%s-%s", constants.AWSServicePrefix, profile)
	}

	// Use our fixed binary path for consistent keychain access
	execPath := GetSeshBinaryPath()

	// Use security command to store secret with -T flag to restrict access
	addCmd := exec.Command("security", "add-generic-password",
		"-a", user,
		"-s", serviceName,
		"-w", secretStr,
		"-U",           // Update if exists
		"-T", execPath, // Only allow the sesh binary to access this item
	)
	err = addCmd.Run()
	if err != nil {
		fmt.Println("❌ Failed to store secret in keychain")
		os.Exit(1)
	}

	// Also store the MFA serial ARN
	var serialServiceName string
	if profile == "" {
		// For default profile, use "default" as the profile name
		serialServiceName = fmt.Sprintf("%s-default", constants.AWSServiceMFAPrefix)
	} else {
		serialServiceName = fmt.Sprintf("%s-%s", constants.AWSServiceMFAPrefix, profile)
	}
	addSerialCmd := exec.Command("security", "add-generic-password",
		"-a", user,
		"-s", serialServiceName,
		"-w", mfaArn,
		"-U",           // Update if exists
		"-T", execPath, // Only allow the sesh binary to access this item
	)
	err = addSerialCmd.Run()
	if err != nil {
		fmt.Println("❌ Failed to store MFA serial in keychain")
		os.Exit(1)
	}

	// Store metadata for better organization and retrieval
	description := "AWS MFA"
	if profile != "" {
		description = fmt.Sprintf("AWS MFA for profile %s", profile)
	}

	// Store metadata - CRITICAL for entry retrieval
	err = keychain.StoreEntryMetadata(constants.AWSServicePrefix, serviceName, user, description)
	if err != nil {
		fmt.Println("❌ Failed to store metadata for entry retrieval")
		fmt.Println("⚠️ This entry might not appear when listing available AWS profiles")
		fmt.Println("⚠️ You might need to create the entry again or check keychain permissions")
		os.Exit(1)
	}

	fmt.Println("\n✅ Setup complete! You can now use 'sesh' to generate AWS temporary credentials.")
	fmt.Println()
	fmt.Println("🚀 Next steps:")
	fmt.Println("1. Run 'sesh' to generate a temporary session token")
	fmt.Println("2. The credentials will be automatically exported to your shell")
	fmt.Println("3. You can now use AWS CLI commands with MFA security")

	if profile == "" {
		fmt.Println("\nTo use this setup, run: sesh")
		fmt.Println("(The default AWS profile will be used)")
	} else {
		fmt.Printf("\nTo use this setup, run: sesh --profile %s\n", profile)
	}
}

// setupGenericTOTP configures a generic TOTP service
// captureAndProcessQRCode takes a screenshot and extracts a TOTP secret from a QR code
func captureAndProcessQRCode() (string, error) {
	// Create a temp file for the screenshot
	tempFile := filepath.Join(os.TempDir(), fmt.Sprintf("sesh-qr-%d.png", time.Now().UnixNano()))
	defer os.Remove(tempFile) // Clean up when done

	// Use screencapture on macOS
	cmd := exec.Command("screencapture", "-i", tempFile)
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("failed to capture screenshot: %w", err)
	}

	// Check if the user canceled (file would be empty or very small)
	fileInfo, err := os.Stat(tempFile)
	if err != nil || fileInfo.Size() < 100 {
		return "", fmt.Errorf("screenshot capture was canceled or failed")
	}

	// Open and decode the image
	file, err := os.Open(tempFile)
	if err != nil {
		return "", fmt.Errorf("failed to open screenshot: %w", err)
	}
	defer file.Close()

	img, err := png.Decode(file)
	if err != nil {
		return "", fmt.Errorf("failed to decode image: %w", err)
	}

	// Convert to the format required by gozxing
	bmp, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		return "", fmt.Errorf("failed to process image for QR reading: %w", err)
	}

	// Set up QR code reader
	reader := qrcode.NewQRCodeReader()
	result, err := reader.Decode(bmp, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decode QR code: %w", err)
	}

	// Extract secret from otpauth URI
	otpauthURL := result.GetText()
	if !strings.HasPrefix(otpauthURL, "otpauth://") {
		return "", fmt.Errorf("not a valid otpauth URL: %s", otpauthURL)
	}

	parsedURL, err := url.Parse(otpauthURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse otpauth URL: %w", err)
	}

	query := parsedURL.Query()
	secret := query.Get("secret")
	if secret == "" {
		return "", fmt.Errorf("no secret found in QR code")
	}

	return secret, nil
}

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

	// Get TOTP secret
	fmt.Println("Enter your TOTP secret key (this will not be echoed):")
	secret, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Println("❌ Failed to read secret")
		os.Exit(1)
	}
	fmt.Println() // Add a newline after the hidden input

	// Generate two consecutive TOTP codes to help with setup
	secretStr := string(secret)
	secretStr = strings.TrimSpace(secretStr)

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
	execPath := GetSeshBinaryPath()

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
		"-w", string(secret),
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
