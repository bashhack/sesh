package setup

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/bashhack/sesh/internal/totp"
)

var (
	clearWithWriter      = clearWithWriterImpl
	clear                = clearImpl
	RunWizardWithOptions = runWizardWithOptions
)

// WizardOptions contains all configurable options for the setup wizard
type WizardOptions struct {
	Reader            io.Reader      // Input reader (defaults to os.Stdin)
	Writer            io.Writer      // Output writer (defaults to os.Stdout)
	ErrorWriter       io.Writer      // Error writer (defaults to os.Stderr)
	ExecCommand       CommandRunner  // Command runner (defaults to exec.Command)
	OsExit            func(int)      // Exit function (defaults to os.Exit)
	TOTPProvider      totp.Provider  // TOTP provider (defaults to totp.NewDefaultProvider())
	SkipClear         bool           // Skip terminal clearing (useful for testing)
	AppExecutablePath string         // Path to the application executable for keychain binding
}

// CommandRunner is an interface that abstracts exec.Command functionality
type CommandRunner interface {
	Command(command string, args ...string) *exec.Cmd
}

// DefaultCommandRunner is the standard implementation using exec.Command
type DefaultCommandRunner struct{}

// Command wraps exec.Command
func (r *DefaultCommandRunner) Command(command string, args ...string) *exec.Cmd {
	return exec.Command(command, args...)
}

// RunWizard runs the setup wizard with default options
func RunWizard() {
	RunWizardWithOptions(WizardOptions{})
}

// runWizardWithOptions runs the setup wizard with custom options
func runWizardWithOptions(opts WizardOptions) {
	if opts.Reader == nil {
		opts.Reader = os.Stdin
	}
	if opts.Writer == nil {
		opts.Writer = os.Stdout
	}
	if opts.ErrorWriter == nil {
		opts.ErrorWriter = os.Stderr
	}
	if opts.ExecCommand == nil {
		opts.ExecCommand = &DefaultCommandRunner{}
	}
	if opts.OsExit == nil {
		opts.OsExit = os.Exit
	}
	if opts.TOTPProvider == nil {
		opts.TOTPProvider = totp.NewDefaultProvider()
	}

	reader := bufio.NewReader(opts.Reader)

	if !opts.SkipClear {
		clearWithWriter(opts.Writer, opts.ExecCommand)
	}

	fmt.Fprintln(opts.Writer, "✨ Welcome to sesh – your terminal-native AWS MFA helper.")
	fmt.Fprintln(opts.Writer, "Let's get you set up.")
	fmt.Fprintln(opts.Writer)

	fmt.Fprintln(opts.Writer, "🔐 Step 1: Set up a virtual MFA device in the AWS Console")
	fmt.Fprintln(opts.Writer, "If you haven't already, go to:")
	fmt.Fprintln(opts.Writer, "  👉 https://console.aws.amazon.com/iam/home#/security_credentials")
	fmt.Fprintln(opts.Writer)
	fmt.Fprintln(opts.Writer, "Enable a virtual MFA device, and when prompted, choose to show the secret key.")

	fmt.Fprint(opts.Writer, "📋 Paste your AWS MFA Base32 secret key here: ")
	secret, _ := reader.ReadString('\n')
	secret = strings.TrimSpace(secret)

	fmt.Fprintln(opts.Writer, "\n🔢 Generating two consecutive MFA codes for AWS setup...")
	currentCode, nextCode, err := opts.TOTPProvider.GenerateConsecutiveCodes(secret)
	if err != nil {
		fmt.Fprintf(opts.ErrorWriter, "❌ Failed to generate MFA codes: %v\n", err)
		opts.OsExit(1)
		return
	}

	fmt.Fprintln(opts.Writer, "\n📱 Enter these two consecutive codes in AWS when prompted:")
	fmt.Fprintf(opts.Writer, "  First code:  %s\n", currentCode)
	fmt.Fprintf(opts.Writer, "  Second code: %s\n", nextCode)
	fmt.Fprintln(opts.Writer, "\nℹ️  You can enter both codes immediately one after another - no need to wait between them.")
	fmt.Fprintln(opts.Writer, "⏱️  Complete the AWS setup within 30 seconds of seeing these codes.")

	fmt.Fprint(opts.Writer, "\n👤 Keychain account name (press Enter to use your current macOS username): ")
	account, _ := reader.ReadString('\n')
	account = strings.TrimSpace(account)
	if account == "" {
		whoamiCmd := opts.ExecCommand.Command("whoami")
		accountBytes, err := whoamiCmd.Output()
		if err != nil {
			fmt.Fprintf(opts.ErrorWriter, "Could not determine current user: %v\n", err)
			opts.OsExit(1)
			return
		}
		account = strings.TrimSpace(string(accountBytes))
	}

	service := "sesh-mfa"

	fmt.Fprintf(opts.Writer, "💾 Saving your secret to Keychain as account='%s', service='%s'...\n", account, service)

	execPath := opts.AppExecutablePath
	if execPath == "" {
		var execPathErr error
		execPath, execPathErr = os.Executable()
		if execPathErr != nil {
			execPath = "/usr/local/bin/sesh" // Fallback path
		}
	}

	// Using application binding for enhanced security via macOS Keychain -T
	// For more, see: manpage for security(1) for the add-generic-password
	// command and review the -T flag
	securityCmd := opts.ExecCommand.Command("security", "add-generic-password",
		"-a", account,
		"-s", service,
		"-w", secret,
		"-T", execPath,
		"-U")

	err = securityCmd.Run()
	if err != nil {
		fmt.Fprintf(opts.ErrorWriter, "❌ Failed to store secret in Keychain: %v\n", err)
		opts.OsExit(1)
		return
	}

	fmt.Fprintln(opts.Writer, "\n✅ MFA secret successfully stored in Keychain!")

	fmt.Fprintln(opts.Writer, "\n🔍 Looking for your MFA device in AWS...")

	awsCmd := opts.ExecCommand.Command("aws", "iam", "list-mfa-devices", "--output", "json")
	devices, err := awsCmd.Output()

	if err != nil {
		fmt.Fprintf(opts.ErrorWriter, "❗ Could not list MFA devices from AWS. You might need to specify your MFA ARN manually.\n")
	} else {
		var response struct {
			MFADevices []struct {
				SerialNumber string `json:"SerialNumber"`
				UserName     string `json:"UserName"`
			} `json:"MFADevices"`
		}

		if err := json.Unmarshal(devices, &response); err != nil {
			fmt.Fprintf(opts.ErrorWriter, "❗ Could not parse MFA device list. You might need to specify your MFA ARN manually.\n")
		} else if len(response.MFADevices) > 0 {
			var serialToUse string

			if len(response.MFADevices) > 1 {
				fmt.Fprintln(opts.Writer, "\n📱 Multiple MFA devices found. Which one did you just set up?")
				for i, device := range response.MFADevices {
					fmt.Fprintf(opts.Writer, "  %d. %s (%s)\n", i+1, device.SerialNumber, device.UserName)
				}

				fmt.Fprint(opts.Writer, "\nEnter number [1]: ")
				choice, _ := reader.ReadString('\n')
				choice = strings.TrimSpace(choice)

				// Default to first device
				index := 0
				if choice != "" {
					if idx, err := strconv.Atoi(choice); err == nil && idx >= 1 && idx <= len(response.MFADevices) {
						index = idx - 1
					}
				}

				serialToUse = response.MFADevices[index].SerialNumber
			} else {
				serialToUse = response.MFADevices[0].SerialNumber
			}

			fmt.Fprintf(opts.Writer, "\n💾 Saving your MFA device ARN for future use: %s\n", serialToUse)

			securityCmd := opts.ExecCommand.Command("security", "add-generic-password",
				"-a", account,
				"-s", "sesh-mfa-serial",
				"-w", serialToUse,
				"-T", execPath, // Use the same app binding
				"-U")

			err := securityCmd.Run()
			if err != nil {
				fmt.Fprintf(opts.ErrorWriter, "⚠️ Could not store MFA serial in keychain. You might need to specify it manually.\n")
			}
		}
	}

	fmt.Fprintln(opts.Writer, "\n📝 Next steps:")
	fmt.Fprintln(opts.Writer, "  1. Make sure the sesh binary is installed and in your PATH:")
	fmt.Fprintln(opts.Writer, "     - For development: run 'make install' or add this directory to your PATH")
	fmt.Fprintln(opts.Writer, "     - For regular use: run 'make install' or install via Homebrew")
	fmt.Fprintln(opts.Writer, "\n  2. Configure your AWS CLI if you haven't already:")
	fmt.Fprintln(opts.Writer, "     - Run 'aws configure' to set up your AWS access keys")
	fmt.Fprintln(opts.Writer, "\n  3. Run sesh to get temporary credentials:")
	fmt.Fprintln(opts.Writer, "     - With shell integration: 'sesh'")
	fmt.Fprintln(opts.Writer, "     - Without shell integration: 'eval \"$(sesh)\"'")
	fmt.Fprintln(opts.Writer)
}

// clearImpl clears the terminal using the default command runner
func clearImpl() {
	clearWithWriter(os.Stdout, &DefaultCommandRunner{})
}

// clearWithWriterImpl clears the terminal with a specific writer and command runner
func clearWithWriterImpl(w io.Writer, runner CommandRunner) {
	cmd := runner.Command("clear")
	cmd.Stdout = w
	_ = cmd.Run()
}
