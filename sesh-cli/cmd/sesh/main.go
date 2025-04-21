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
	// Create a standard flag set with common flags
	fs := flag.NewFlagSet(args[0], flag.ExitOnError)

	// Common flags
	serviceName := fs.String("service", "aws", "Service provider to use (aws, totp)")
	showVersion := fs.Bool("version", false, "Show version information")
	showHelp := fs.Bool("help", false, "Show usage")
	listServices := fs.Bool("list-services", false, "List available service providers")
	listEntries := fs.Bool("list", false, "List entries for selected service")
	deleteEntry := fs.String("delete", "", "Delete entry for selected service (specify entry ID)")
	runSetup := fs.Bool("setup", false, "Run setup wizard for selected service")
	copyClipboard := fs.Bool("clip", false, "Copy code to clipboard instead of printing credentials")

	// Parse flags to handle global commands (version/help/list-services)
	// Use a custom error handler that doesn't exit on unknown flags
	firstPassErr := fs.Parse(args[1:])
	if firstPassErr != nil && firstPassErr != flag.ErrHelp {
		// Continue anyway, we'll handle the real error in the second pass
		fmt.Fprintf(app.Stderr, "DEBUG: First pass flag parsing encountered: %v\n", firstPassErr)
	}

	// Handle global commands first
	if *showVersion {
		app.ShowVersion()
		return
	}

	if *showHelp {
		printUsage()
		return
	}

	if *listServices {
		app.ListProviders()
		return
	}

	// Get the selected provider (use aws as default if service flag isn't seen)
	serviceVal := *serviceName
	provider, err := app.Registry.GetProvider(serviceVal)
	if err != nil {
		fmt.Fprintf(app.Stderr, "❌ %v\n", err)
		app.ListProviders()
		app.Exit(1)
		return
	}
	
	// Set up provider flags
	provider.SetupFlags(fs)
	
	// Do a full parse now that all flags are registered
	// Reset flag values in case they were set incorrectly in the first pass
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "list" {
			fmt.Fprintf(app.Stderr, "DEBUG: List flag was set in first pass to %v\n", *listEntries)
		}
	})
	
	// Parse the flags again, with all provider flags registered
	fs = flag.NewFlagSet(args[0], flag.ExitOnError)
	
	// Redefine base flags
	serviceName = fs.String("service", "aws", "Service provider to use (aws, totp)")
	showVersion = fs.Bool("version", false, "Show version information")
	showHelp = fs.Bool("help", false, "Show usage")
	listServices = fs.Bool("list-services", false, "List available service providers")
	listEntries = fs.Bool("list", false, "List entries for selected service")
	deleteEntry = fs.String("delete", "", "Delete entry for selected service (specify entry ID)")
	runSetup = fs.Bool("setup", false, "Run setup wizard for selected service")
	copyClipboard = fs.Bool("clip", false, "Copy code to clipboard instead of printing credentials")
	
	// Setup provider flags
	provider.SetupFlags(fs)
	
	// Parse all flags
	if err := fs.Parse(args[1:]); err != nil {
		fmt.Fprintf(app.Stderr, "Error parsing arguments: %v\n", err)
		app.Exit(1)
		return
	}

	// Handle provider-specific commands
	if *listEntries {
		if err := app.ListEntries(*serviceName); err != nil {
			fmt.Fprintf(app.Stderr, "❌ %v\n", err)
			app.Exit(1)
		}
		return
	}

	if *deleteEntry != "" {
		if err := app.DeleteEntry(*serviceName, *deleteEntry); err != nil {
			fmt.Fprintf(app.Stderr, "❌ %v\n", err)
			app.Exit(1)
		}
		return
	}

	if *runSetup {
		if err := app.RunSetup(*serviceName); err != nil {
			fmt.Fprintf(app.Stderr, "❌ Setup failed: %v\n", err)
			app.Exit(1)
		}
		return
	}

	// Handle the main action: either copy to clipboard or generate credentials
	if *copyClipboard {
		if err := app.CopyToClipboard(*serviceName); err != nil {
			fmt.Fprintf(app.Stderr, "❌ %v\n", err)
			app.Exit(1)
		}
	} else {
		if err := app.GenerateCredentials(*serviceName); err != nil {
			fmt.Fprintf(app.Stderr, "❌ %v\n", err)
			app.Exit(1)
		}
	}
}

func printUsage() {
	fmt.Println("Usage: sesh [options]")
	fmt.Println("\nCommon options:")
	fmt.Println("  --service, -service           Service provider to use (aws, totp) (default \"aws\")")
	fmt.Println("  --list, -list                 List entries for selected service")
	fmt.Println("  --delete, -delete string      Delete entry for selected service (specify entry ID)")
	fmt.Println("  --setup, -setup               Run setup wizard for selected service")
	fmt.Println("  --clip, -clip                 Copy code to clipboard instead of printing credentials")
	fmt.Println("  --list-services, -list-services  List available service providers")
	fmt.Println("  --version, -version           Show version information")
	fmt.Println("  --help, -help                 Show usage")
	fmt.Println("\nProvider-specific options:")
	fmt.Println("\nAWS provider options:")
	fmt.Println("  --profile, -profile string     AWS CLI profile to use")
	fmt.Println("  --serial, -serial string       MFA device serial number (optional)")
	fmt.Println("  --keychain-user, -keychain-user string  macOS Keychain username (optional)")
	fmt.Println("  --keychain-name, -keychain-name string  macOS Keychain service name (default \"sesh-mfa\")")
	fmt.Println("\nTOTP provider options:")
	fmt.Println("  --service-name, -service-name string  Name of the service to authenticate with")
	fmt.Println("  --keychain-user, -keychain-user string  macOS Keychain username (optional)")
	fmt.Println("  --label, -label string         Label to identify this TOTP entry")
	fmt.Println("\nExamples:")
	fmt.Println("  sesh                                   Generate AWS credentials")
	fmt.Println("  sesh --service totp --service-name github   Generate TOTP code for GitHub")
	fmt.Println("  sesh --clip                            Copy AWS credentials to clipboard")
	fmt.Println("  sesh --service totp --service-name bank --clip   Copy TOTP code for bank to clipboard")
	fmt.Println("  sesh --list-services                   List available service providers")
	fmt.Println("  sesh --service totp --list             List all TOTP services")
	fmt.Println("  sesh --service totp --setup            Run setup wizard for TOTP")
}