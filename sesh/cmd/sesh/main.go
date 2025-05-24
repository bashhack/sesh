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
	//// Set up global usage handlers for -h flag
	//flag.Usage = printUsage // NOTE: Shouldn't need this given edit to run()

	app := NewDefaultApp()
	run(app, os.Args)
}

// run is the testable entrypoint for the application
func run(app *App, args []string) {
	fs := flag.NewFlagSet(args[0], flag.ExitOnError)

	fs.Usage = printUsage
	// Also override the flag.CommandLine Usage for -h handling
	flag.Usage = printUsage

	serviceName := fs.String("service", "", "Service provider to use (aws, totp)") // NOTE: I'm toying with maybe having no default of "aws" here...
	showVersion := fs.Bool("version", false, "Show version information")
	showHelp := fs.Bool("help", false, "Show usage")
	listServices := fs.Bool("list-services", false, "List available service providers")
	listEntries := fs.Bool("list", false, "List entries for selected service")
	deleteEntry := fs.String("delete", "", "Delete entry for selected service (specify entry ID)")
	runSetup := fs.Bool("setup", false, "Run setup wizard for selected service")
	copyClipboard := fs.Bool("clip", false, "Copy code to clipboard instead of printing credentials")
	noSubshell := fs.Bool("no-subshell", false, "Print environment variables instead of launching subshell (AWS only)")

	// We need to avoid duplicate flags between providers
	// Create a map to track which flags have been registered
	registeredFlags := make(map[string]bool)

	// Pre-register base flags
	registeredFlags["service"] = true
	registeredFlags["version"] = true
	registeredFlags["help"] = true
	registeredFlags["list-services"] = true
	registeredFlags["list"] = true
	registeredFlags["delete"] = true
	registeredFlags["setup"] = true
	registeredFlags["clip"] = true
	registeredFlags["no-subshell"] = true

	// Create a safe flag set wrapper to avoid duplicates
	safeFlagSet := &safeFlagSet{fs: fs, registered: registeredFlags}

	// Register all provider flags through our safe wrapper
	for _, p := range app.Registry.ListProviders() {
		err := p.SetupFlags(safeFlagSet)
		if err != nil {
			fmt.Fprintf(app.Stderr, "❌ error initializing providers: %v\n", err)
			app.Exit(1)
		}
	}

	// Now we can do a single parse with all flags registered
	if err := fs.Parse(args[1:]); err != nil {
		fmt.Fprintf(app.Stderr, "❌ error parsing arguments: %v\n", err)
		app.Exit(1)
		return
	}

	// Handle global commands first that don't need provider-specific flags
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

	// ...NOTE: I'm toying with the idea of having no default service provider, so would bail out here if serviceName is empty
	if *serviceName == "" {
		fmt.Fprintln(app.Stderr, "❌ No service provider specified. Use --service to select a provider.")
		app.ListProviders()
		app.Exit(1)
		return
	}

	_, err := app.Registry.GetProvider(*serviceName)
	if err != nil {
		fmt.Fprintf(app.Stderr, "❌ %v\n", err)
		app.ListProviders()
		app.Exit(1)
		return
	}

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

	if *copyClipboard {
		if err := app.CopyToClipboard(*serviceName); err != nil {
			fmt.Fprintf(app.Stderr, "❌ %v\n", err)
			app.Exit(1)
		}
	} else if *serviceName == "aws" && !*noSubshell {
		// For AWS service, use subshell to provide an isolated credential environment
		if err := app.LaunchSubshell(*serviceName); err != nil {
			fmt.Fprintf(app.Stderr, "❌ %v\n", err)
			app.Exit(1)
		}
	} else {
		// For all other services, or AWS with --no-subshell, use regular credential output
		if err := app.GenerateCredentials(*serviceName); err != nil {
			fmt.Fprintf(app.Stderr, "❌ %v\n", err)
			app.Exit(1)
		}
	}
}

// safeFlagSet wraps a flag.FlagSet to prevent duplicate flags
type safeFlagSet struct {
	fs         *flag.FlagSet
	registered map[string]bool
}

// StringVar safely registers a string flag if it doesn't already exist
func (s *safeFlagSet) StringVar(p *string, name string, value string, usage string) {
	if _, exists := s.registered[name]; !exists {
		s.registered[name] = true
		s.fs.StringVar(p, name, value, usage)
	}
}

// BoolVar safely registers a bool flag if it doesn't already exist
func (s *safeFlagSet) BoolVar(p *bool, name string, value bool, usage string) {
	if _, exists := s.registered[name]; !exists {
		s.registered[name] = true
		s.fs.BoolVar(p, name, value, usage)
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
	fmt.Println("\nTOTP provider options:")
	fmt.Println("  --service-name, -service-name string  Name of the service to authenticate with (required)")
	fmt.Println("  --profile, -profile string         Profile name for multiple accounts with the same service")
	fmt.Println("\nExamples:")
	fmt.Println("  sesh                                   Generate AWS credentials")
	fmt.Println("  sesh --service totp --service-name github   Generate TOTP code for GitHub")
	fmt.Println("  sesh --service totp --service-name bank --clip   Copy TOTP code for bank to clipboard")
	fmt.Println("  sesh --list-services                   List available service providers")
	fmt.Println("  sesh --service totp --list             List all TOTP services")
	fmt.Println("  sesh --service totp --setup            Run setup wizard for TOTP")
}
