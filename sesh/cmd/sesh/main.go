package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/bashhack/sesh/internal/provider"
	awsProvider "github.com/bashhack/sesh/internal/provider/aws"
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
	// Early exit for help/version without needing service
	for _, arg := range args[1:] {
		switch arg {
		case "--help", "-help", "-h":
			printUsage()
			return
		case "--version", "-version":
			app.ShowVersion()
			return
		case "--list-services", "-list-services":
			app.ListProviders()
			return
		}
	}

	// Extract service name from args
	serviceName := extractServiceName(args)
	if serviceName == "" {
		fmt.Fprintln(app.Stderr, "❌ No service provider specified. Use --service to select a provider.")
		app.ListProviders()
		app.Exit(1)
		return
	}

	// Validate service exists
	provider, err := app.Registry.GetProvider(serviceName)
	if err != nil {
		fmt.Fprintf(app.Stderr, "❌ %v\n", err)
		app.ListProviders()
		app.Exit(1)
		return
	}

	// Now create flagset with provider-specific flags
	fs := flag.NewFlagSet(args[0], flag.ExitOnError)
	
	// Set custom usage that includes provider info
	fs.Usage = func() {
		printProviderUsage(serviceName, provider)
	}

	// Register common flags
	serviceFlag := fs.String("service", serviceName, "Service provider to use")
	showVersion := fs.Bool("version", false, "Show version information")
	showHelp := fs.Bool("help", false, "Show usage")
	listServices := fs.Bool("list-services", false, "List available service providers")
	listEntries := fs.Bool("list", false, "List entries for selected service")
	deleteEntry := fs.String("delete", "", "Delete entry for selected service")
	runSetup := fs.Bool("setup", false, "Run setup wizard for selected service")
	copyClipboard := fs.Bool("clip", false, "Copy code to clipboard")

	// Register provider-specific flags
	if err := provider.SetupFlags(fs); err != nil {
		fmt.Fprintf(app.Stderr, "❌ Error setting up provider flags: %v\n", err)
		app.Exit(1)
		return
	}

	// Parse all flags
	if err := fs.Parse(args[1:]); err != nil {
		fmt.Fprintf(app.Stderr, "❌ Error parsing arguments: %v\n", err)
		app.Exit(1)
		return
	}

	// Verify service wasn't changed
	if *serviceFlag != serviceName {
		fmt.Fprintf(app.Stderr, "❌ Service provider cannot be changed after initial selection\n")
		app.Exit(1)
		return
	}

	// Handle commands that were re-parsed
	if *showVersion {
		app.ShowVersion()
		return
	}

	if *showHelp {
		printProviderUsage(serviceName, provider)
		return
	}

	if *listServices {
		app.ListProviders()
		return
	}

	// Provider-specific operations
	if *listEntries {
		if err := app.ListEntries(serviceName); err != nil {
			fmt.Fprintf(app.Stderr, "❌ %v\n", err)
			app.Exit(1)
		}
		return
	}

	if *deleteEntry != "" {
		if err := app.DeleteEntry(serviceName, *deleteEntry); err != nil {
			fmt.Fprintf(app.Stderr, "❌ %v\n", err)
			app.Exit(1)
		}
		return
	}

	if *runSetup {
		if err := app.RunSetup(serviceName); err != nil {
			fmt.Fprintf(app.Stderr, "❌ Setup failed: %v\n", err)
			app.Exit(1)
		}
		return
	}

	// Main operation - generate credentials
	if *copyClipboard {
		if err := app.CopyToClipboard(serviceName); err != nil {
			fmt.Fprintf(app.Stderr, "❌ %v\n", err)
			app.Exit(1)
		}
	} else if serviceName == "aws" {
		// Check if AWS provider wants subshell
		if awsP, ok := provider.(*awsProvider.Provider); ok && awsP.ShouldUseSubshell() {
			if err := app.LaunchSubshell(serviceName); err != nil {
				fmt.Fprintf(app.Stderr, "❌ %v\n", err)
				app.Exit(1)
			}
		} else {
			if err := app.GenerateCredentials(serviceName); err != nil {
				fmt.Fprintf(app.Stderr, "❌ %v\n", err)
				app.Exit(1)
			}
		}
	} else {
		if err := app.GenerateCredentials(serviceName); err != nil {
			fmt.Fprintf(app.Stderr, "❌ %v\n", err)
			app.Exit(1)
		}
	}
}

// extractServiceName manually parses args to find --service value
func extractServiceName(args []string) string {
	for i := 1; i < len(args); i++ {
		// Handle --service <value>
		if args[i] == "--service" || args[i] == "-service" {
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				return args[i+1]
			}
		}
		// Handle --service=<value>
		if strings.HasPrefix(args[i], "--service=") {
			return strings.TrimPrefix(args[i], "--service=")
		}
		if strings.HasPrefix(args[i], "-service=") {
			return strings.TrimPrefix(args[i], "-service=")
		}
	}
	return ""
}

func printUsage() {
	fmt.Println("Usage: sesh [options]")
	fmt.Println("\nCommon options:")
	fmt.Println("  --service, -service           Service provider to use (aws, totp) [REQUIRED]")
	fmt.Println("  --list, -list                 List entries for selected service")
	fmt.Println("  --delete, -delete string      Delete entry for selected service")
	fmt.Println("  --setup, -setup               Run setup wizard for selected service")
	fmt.Println("  --clip, -clip                 Copy code to clipboard")
	fmt.Println("  --list-services, -list-services  List available service providers")
	fmt.Println("  --version, -version           Show version information")
	fmt.Println("  --help, -help                 Show usage")
	fmt.Println("\nExamples:")
	fmt.Println("  sesh --service aws                     Generate AWS credentials")
	fmt.Println("  sesh --service totp --service-name github   Generate TOTP code for GitHub")
	fmt.Println("  sesh --list-services                   List available providers")
	fmt.Println("\nFor provider-specific help:")
	fmt.Println("  sesh --service <provider> --help")
}

// printProviderUsage prints usage for a specific provider
func printProviderUsage(serviceName string, p provider.ServiceProvider) {
	fmt.Printf("Usage: sesh --service %s [options]\n\n", serviceName)
	
	fmt.Println("Common options:")
	fmt.Println("  --service string              Service provider to use")
	fmt.Println("  --list                        List entries for selected service")
	fmt.Println("  --delete string               Delete entry for selected service")
	fmt.Println("  --setup                       Run setup wizard for selected service")
	fmt.Println("  --clip                        Copy code to clipboard")
	fmt.Println("  --help                        Show this help")
	fmt.Println("  --version                     Show version information")
	
	// Provider-specific flags
	flagInfo := p.GetFlagInfo()
	if len(flagInfo) > 0 {
		fmt.Printf("\n%s provider options:\n", strings.Title(serviceName))
		for _, flag := range flagInfo {
			required := ""
			if flag.Required {
				required = " [REQUIRED]"
			}
			fmt.Printf("  --%s %s%s\n    %s\n", flag.Name, flag.Type, required, flag.Description)
		}
	}
	
	// Examples
	fmt.Println("\nExamples:")
	switch serviceName {
	case "aws":
		fmt.Println("  sesh --service aws                     Generate AWS credentials (subshell)")
		fmt.Println("  sesh --service aws --no-subshell       Print AWS credentials")
		fmt.Println("  sesh --service aws --profile dev       Use 'dev' AWS profile")
		fmt.Println("  sesh --service aws --setup             Set up AWS credentials")
	case "totp":
		fmt.Println("  sesh --service totp --service-name github     Generate TOTP for GitHub")
		fmt.Println("  sesh --service totp --service-name github --clip   Copy TOTP to clipboard")
		fmt.Println("  sesh --service totp --setup            Set up new TOTP service")
		fmt.Println("  sesh --service totp --list             List all TOTP services")
	}
}
