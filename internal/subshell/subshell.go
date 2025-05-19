package subshell

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type Config struct {
	ServiceName string
	Variables   map[string]string
	Expiry      time.Time

	ShellCustomizer ShellCustomizer
}

type ShellCustomizer interface {
	GetZshInitScript() string

	GetBashInitScript() string

	GetFallbackInitScript() string

	GetPromptPrefix() string

	GetWelcomeMessage() string
}

//func Launch(config Config, stdout, stderr io.Writer) error {
//	// Force debug info output to be cleared
//	os.Remove("/tmp/sesh_debug.txt")
//	debug("=== Launch function called ===")
//	debug("stdout type: %T, stderr type: %T", stdout, stderr)
//	debug("ShellCustomizer type: %T", config.ShellCustomizer)
//	if os.Getenv("SESH_ACTIVE") == "1" {
//		return fmt.Errorf("already in a sesh environment, nested sessions are not supported.\nPlease exit the current sesh shell first with 'exit' or Ctrl+D")
//	}
//
//	// Get a clean environment, without any ZDOTDIR or other variables that might interfere
//	env := os.Environ()
//
//	// Filter critical environment variables that might interfere with shell behavior
//	env = filterEnv(env, "ZDOTDIR")
//
//	debug("After filtering ZDOTDIR, environment length: %d", len(env))
//
//	for key, value := range config.Variables {
//		env = filterEnv(env, key)
//		env = append(env, fmt.Sprintf("%s=%s", key, value))
//	}
//
//	env = append(env, fmt.Sprintf("SESH_ACTIVE=1"))
//	env = append(env, fmt.Sprintf("SESH_SERVICE=%s", config.ServiceName))
//	env = append(env, "SESH_DISABLE_INTEGRATION=1")
//
//	env = append(env, fmt.Sprintf("SESH_START_TIME=%d", time.Now().Unix()))
//	if !config.Expiry.IsZero() {
//		env = append(env, fmt.Sprintf("SESH_EXPIRY=%d", config.Expiry.Unix()))
//		env = append(env, fmt.Sprintf("SESH_TOTAL_DURATION=%d", config.Expiry.Unix()-time.Now().Unix()))
//	}
//
//	shell := os.Getenv("SHELL")
//	if shell == "" {
//		shell = "/bin/sh"
//	}
//
//	var cmd *exec.Cmd
//	var shellSetupErr error
//
//	switch {
//	case shell == "/bin/zsh" || filepath.Base(shell) == "zsh":
//		cmd, shellSetupErr = SetupZshShell(shell, config, env)
//	case shell == "/bin/bash" || filepath.Base(shell) == "bash":
//		cmd, shellSetupErr = setupBashShell(shell, config, env)
//	default:
//		cmd, shellSetupErr = setupFallbackShell(shell, config, env)
//	}
//	if shellSetupErr != nil {
//		return fmt.Errorf("failed to set up shell: %w", shellSetupErr)
//	}
//
//	// Write debug info
//	debugFile, _ := os.OpenFile("/tmp/sesh_debug.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
//	if debugFile != nil {
//		defer debugFile.Close()
//		fmt.Fprintf(debugFile, "=== SESH DEBUG ===\n")
//		fmt.Fprintf(debugFile, "Shell: %s\n", shell)
//		fmt.Fprintf(debugFile, "Types - stdout: %T, stderr: %T\n", stdout, stderr)
//		fmt.Fprintf(debugFile, "os.Stdout: %T, os.Stderr: %T\n", os.Stdout, os.Stderr)
//		fmt.Fprintf(debugFile, "Environment variables:\n")
//		for _, envVar := range env {
//			if len(envVar) >= 8 && envVar[:8] == "ZDOTDIR=" {
//				zdir := envVar[8:]
//				fmt.Fprintf(debugFile, "ZDOTDIR set to: %s\n", zdir)
//				zshrcPath := filepath.Join(zdir, ".zshrc")
//				fmt.Fprintf(debugFile, "Looking for .zshrc at: %s\n", zshrcPath)
//				fileContent, err := os.ReadFile(zshrcPath)
//				if err != nil {
//					fmt.Fprintf(debugFile, "Error reading .zshrc: %v\n", err)
//				} else {
//					fmt.Fprintf(debugFile, ".zshrc content begins:\n")
//					fmt.Fprintf(debugFile, "%s\n", string(fileContent))
//					fmt.Fprintf(debugFile, ".zshrc content ends\n")
//				}
//			}
//		}
//		fmt.Fprintf(debugFile, "Command args: %v\n", cmd.Args)
//	}
//
//	cmd.Stdin = os.Stdin
//	cmd.Stdout = stdout
//	cmd.Stderr = stderr
//	cmd.Env = env
//
//	// Print the starting message including the welcome message from the customizer
//	fmt.Fprintf(stdout, "Starting secure shell with %s credentials\n", config.ServiceName)
//	if config.ShellCustomizer != nil {
//		welcomeMsg := config.ShellCustomizer.GetWelcomeMessage()
//		if welcomeMsg != "" {
//			fmt.Fprintf(stdout, "%s\n", welcomeMsg)
//		}
//	}
//
//	debug("About to run command: %v", cmd.Args)
//	debug("Command environment has %d variables", len(cmd.Env))
//	debug("Command IO Setup - Stdin: %T, Stdout: %T, Stderr: %T", cmd.Stdin, cmd.Stdout, cmd.Stderr)
//
//	// List all environment variables for debugging
//	debug("Full environment variable list (all %d):", len(cmd.Env))
//	for i, envVar := range cmd.Env {
//		debug("  [%d] %s", i, envVar)
//	}
//
//	// Create a test script to verify function loading
//	testScript := `#!/bin/sh
//echo "Testing if zsh functions are loaded..."
//zsh -c "type sesh_help >/tmp/sesh_function_test.txt 2>&1 || echo 'Function not found' >/tmp/sesh_function_test.txt"
//`
//	os.WriteFile("/tmp/test_sesh_functions.sh", []byte(testScript), 0755)
//	exec.Command("/bin/sh", "/tmp/test_sesh_functions.sh").Run()
//
//	err := cmd.Run()
//
//	debug("Command has completed execution")
//
//	// Check the test result
//	if functionTestResult, readErr := os.ReadFile("/tmp/sesh_function_test.txt"); readErr == nil {
//		debug("Function test result: %s", string(functionTestResult))
//	} else {
//		debug("Could not read function test result: %v", readErr)
//	}
//
//	fmt.Fprintf(stdout, "Exited secure shell\n")
//
//	if err != nil {
//		// ExitError is the standard error type when a shell exits, whether by
//		// normal means (exit command, Ctrl+D) or signals. This is expected behavior
//		// for subshell implementations and shouldn't be reported as an error.
//		// In my testing, tools like Python's virtualenv have similar behavior -
//		// swallowing events like Ctrl+C, for example.
//		var exitError *exec.ExitError
//		if errors.As(err, &exitError) {
//			return nil
//		}
//
//		// Only return truly unexpected errors...
//		return fmt.Errorf("subshell encountered an unexpected error: %w", err)
//	}
//
//	return nil
//}

func SetupZshShell(config Config, env []string) ([]string, error) {
	// Create a temporary ZDOTDIR for zsh
	tmpDir, err := os.MkdirTemp("", "sesh_zsh")
	if err != nil {
		return []string{}, fmt.Errorf("failed to create temp dir for zsh: %w", err)
	}
	zshrc := filepath.Join(tmpDir, ".zshrc")

	// Construct zsh init script with common functions
	if writeErr := os.WriteFile(zshrc, []byte(config.ShellCustomizer.GetZshInitScript()), 0644); writeErr != nil {
		return []string{}, fmt.Errorf("failed to write temp zshrc: %w", writeErr)
	}
	env = append(env, fmt.Sprintf("ZDOTDIR=%s", tmpDir))

	return env, nil
}

func SetupBashShell(config Config) (*os.File, error) {
	// Create a temporary rcfile for bash
	tmpFile, err := os.CreateTemp("", "sesh_bashrc")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp bashrc: %w", err)
	}
	defer tmpFile.Close()

	if _, writeErr := tmpFile.WriteString(config.ShellCustomizer.GetBashInitScript()); writeErr != nil {
		return nil, fmt.Errorf("failed to write temp bashrc: %w", writeErr)
	}

	return tmpFile, nil
}

func SetupFallbackShell(shell string, config Config, env []string) (*exec.Cmd, error) {
	// fallback shell - create a basic script file to define functions
	tmpFile, err := os.CreateTemp("", "sesh_shellrc")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp shellrc: %w", err)
	}
	defer tmpFile.Close()

	if _, writeErr := tmpFile.WriteString(config.ShellCustomizer.GetFallbackInitScript()); writeErr != nil {
		return nil, fmt.Errorf("failed to write temp shellrc: %w", writeErr)
	}

	// Set the environment to show the prompt
	env = append(env, fmt.Sprintf("PS1=%s$ ", config.ShellCustomizer.GetPromptPrefix()))
	env = append(env, fmt.Sprintf("ENV=%s", tmpFile.Name())) // For sh shells

	return exec.Command(shell), nil
}

// filterEnv removes any existing environment variables with the specified key
// This ensures we don't have duplicate environment variables
func filterEnv(env []string, key string) []string {
	var result []string
	prefix := key + "="
	for _, item := range env {
		if len(item) < len(prefix) || item[:len(prefix)] != prefix {
			result = append(result, item)
		}
	}
	return result
}
