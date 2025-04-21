package setup

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/term"
)

// GetCurrentExecutablePath gets the path of the current binary or a valid installed path
func GetCurrentExecutablePath() string {
	// First try os.Executable() to get the current binary path
	selfPath, err := os.Executable()
	if err == nil && selfPath != "" {
		// Check if this path exists
		if _, statErr := os.Stat(selfPath); statErr == nil {
			return selfPath
		}
	}
	
	// Otherwise, check for known installation paths
	knownPaths := []string{
		os.ExpandEnv("$HOME/.local/bin/sesh"),
		"/usr/local/bin/sesh",
		"/opt/homebrew/bin/sesh",
	}
	
	for _, path := range knownPaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	
	// Fall back to the default as a last resort
	return "/usr/local/bin/sesh"
}

// SetSeshBinaryPath is kept for compatibility but no longer used
// We now determine the binary path at the time of each keychain operation
func SetSeshBinaryPath(path string) {
	// No-op - binary path is determined at access time
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

	// Binary path is now determined at the time of keychain operations
	// No explicit path setting needed here

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

	// Try to get MFA devices
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
			fmt.Print("Choose a device (1-n): ")
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

	// Get MFA secret
	fmt.Println("Enter your MFA secret (this will not be echoed):")
	secret, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Println("❌ Failed to read secret")
		os.Exit(1)
	}
	fmt.Println() // Add a newline after the hidden input

	// Store in keychain
	user := getCurrentUser()

	// If a profile is specified, use it as part of the keychain service name
	serviceName := "sesh-mfa"
	if profile != "" {
		serviceName = fmt.Sprintf("sesh-mfa-%s", profile)
	}

	// Get the executable path at the time of execution
	execPath := GetCurrentExecutablePath()

	// Use security command to store secret with -T flag to restrict access
	addCmd := exec.Command("security", "add-generic-password",
		"-a", user,
		"-s", serviceName,
		"-w", string(secret),
		"-U", // Update if exists
		"-T", execPath, // Only allow the sesh binary to access this item
	)
	err = addCmd.Run()
	if err != nil {
		fmt.Println("❌ Failed to store secret in keychain")
		os.Exit(1)
	}

	// Also store the MFA serial ARN
	serialServiceName := "sesh-mfa-serial"
	if profile != "" {
		serialServiceName = fmt.Sprintf("sesh-mfa-serial-%s", profile)
	}
	addSerialCmd := exec.Command("security", "add-generic-password",
		"-a", user,
		"-s", serialServiceName,
		"-w", mfaArn,
		"-U", // Update if exists
		"-T", execPath, // Only allow the sesh binary to access this item
	)
	err = addSerialCmd.Run()
	if err != nil {
		fmt.Println("❌ Failed to store MFA serial in keychain")
		os.Exit(1)
	}

	fmt.Println("✅ Setup complete! You can now use 'sesh' to generate AWS credentials.")
	if profile != "" {
		fmt.Printf("Remember to use 'sesh --profile %s' to use this profile.\n", profile)
	}
}

// setupGenericTOTP configures a generic TOTP service
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

	// Ask for a label/description
	fmt.Print("Enter a label or description (optional): ")
	label, _ := reader.ReadString('\n')
	label = strings.TrimSpace(label)

	// Get TOTP secret
	fmt.Println("Enter your TOTP secret key (this will not be echoed):")
	secret, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Println("❌ Failed to read secret")
		os.Exit(1)
	}
	fmt.Println() // Add a newline after the hidden input

	// Store in keychain
	user := getCurrentUser()

	// Get the executable path at the time of execution
	execPath := GetCurrentExecutablePath()

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
		"-U", // Update if exists
		"-T", execPath, // Only allow the sesh binary to access this item
	)

	// Add description/label if provided
	if label != "" {
		addCmd.Args = append(addCmd.Args, "-j", label)
	}

	err = addCmd.Run()
	if err != nil {
		fmt.Println("❌ Failed to store secret in keychain")
		os.Exit(1)
	}

	fmt.Printf("✅ Setup complete! You can now use 'sesh --service totp --service-name %s", serviceName)
	if profile != "" {
		fmt.Printf(" --profile %s", profile)
	}
	fmt.Println("' to generate TOTP codes.")
	fmt.Println("Use 'sesh --service totp --service-name " + serviceName + " --clip' to copy the code to clipboard.")
}

// getCurrentUser gets the current system user
func getCurrentUser() string {
	user := os.Getenv("USER")
	if user != "" {
		return user
	}

	// If USER env var isn't set, try to get it with whoami
	output, err := exec.Command("whoami").Output()
	if err == nil {
		return strings.TrimSpace(string(output))
	}

	// If all else fails, exit
	fmt.Println("❌ Could not determine current user")
	os.Exit(1)
	return "" // Will never reach here, but needed for compilation
}