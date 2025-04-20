package main

import (
	"flag"
	"fmt"
	"os"
)

// Version information (set by ldflags during build)
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	app := NewDefaultApp()
	run(app, os.Args)
}

// run is the testable entrypoint for the application
func run(app *App, args []string) {
	fs := flag.NewFlagSet(args[0], flag.ExitOnError)

	// Set custom usage that shows double-dash flags
	fs.Usage = func() {
		fmt.Fprintln(app.Stdout, "Usage of sesh:")
		fmt.Fprintln(app.Stdout, "  --help")
		fmt.Fprintln(app.Stdout, "    \tShow usage")
		fmt.Fprintln(app.Stdout, "  --keychain-name string")
		fmt.Fprintln(app.Stdout, "    \tmacOS Keychain service name (default \"sesh-mfa\")")
		fmt.Fprintln(app.Stdout, "  --keychain-user string")
		fmt.Fprintln(app.Stdout, "    \tmacOS Keychain username (optional)")
		fmt.Fprintln(app.Stdout, "  --profile string")
		fmt.Fprintln(app.Stdout, "    \tAWS CLI profile to use")
		fmt.Fprintln(app.Stdout, "  --serial string")
		fmt.Fprintln(app.Stdout, "    \tMFA device serial number (optional)")
		fmt.Fprintln(app.Stdout, "  --setup")
		fmt.Fprintln(app.Stdout, "    \tRun first-time setup flow")
		fmt.Fprintln(app.Stdout, "  --version")
		fmt.Fprintln(app.Stdout, "    \tShow version information")
	}

	profile := fs.String("profile", os.Getenv("AWS_PROFILE"), "AWS CLI profile to use")
	serialArg := fs.String("serial", os.Getenv("SESH_MFA_SERIAL"), "MFA device serial number (optional)")
	keyUser := fs.String("keychain-user", os.Getenv("SESH_KEYCHAIN_USER"), "macOS Keychain username (optional)")

	defaultKeyName := os.Getenv("SESH_KEYCHAIN_NAME")
	if defaultKeyName == "" {
		defaultKeyName = "sesh-mfa"
	}
	keyName := fs.String("keychain-name", defaultKeyName, "macOS Keychain service name")

	runSetup := fs.Bool("setup", false, "Run first-time setup flow")
	showVersion := fs.Bool("version", false, "Show version information")
	showHelp := fs.Bool("help", false, "Show usage")

	// Parse args[1:] to ignore the program name
	if err := fs.Parse(args[1:]); err != nil {
		fmt.Fprintf(app.Stderr, "Error parsing arguments: %v\n", err)
		app.Exit(1)
		return
	}

	if *showVersion {
		app.ShowVersion()
		return
	}

	if *showHelp {
		fs.Usage()
		return
	}

	if *runSetup {
		if err := app.SetupWizard.Run(); err != nil {
			fmt.Fprintf(app.Stderr, "❌ Setup failed: %v\n", err)
			app.Exit(1)
		}
		return
	}

	if !app.CheckAwsCliInstalled() {
		return // ...exit() will have already been called...
	}

	serial, err := app.GetMFASerial(*profile, *keyUser, *serialArg)
	if err != nil {
		app.PrintMFAError(err)
		app.Exit(1)
		return
	}

	// Retrieve from macOS Keychain, see: man security
	secret, err := app.GetTOTPSecret(*keyUser, *keyName)
	if err != nil {
		app.PrintKeychainError(err, *keyUser, *keyName)
		app.Exit(1)
		return
	}

	creds, elapsedTime, err := app.GenerateCredentials(*profile, serial, secret)
	if err != nil {
		app.PrintSessionTokenError(err)
		app.Exit(1)
		return
	}

	fmt.Fprintf(app.Stderr, "✅ Credentials acquired in %.2fs\n", elapsedTime.Seconds())

	app.PrintCredentials(creds)
}
