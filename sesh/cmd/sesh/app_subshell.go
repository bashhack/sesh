package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"
)

// LaunchSubshell launches a new shell with credentials loaded
func (a *App) LaunchSubshell(serviceName string) error {
	p, err := a.Registry.GetProvider(serviceName)
	if err != nil {
		return fmt.Errorf("provider not found: %w", err)
	}

	fmt.Fprintf(a.Stderr, "🔐 Generating credentials for %s...\n", serviceName)
	startTime := time.Now()

	creds, err := p.GetCredentials()
	if err != nil {
		return fmt.Errorf("failed to generate credentials: %w", err)
	}

	elapsedTime := time.Since(startTime)
	fmt.Fprintf(a.Stderr, "✅ Credentials acquired in %.2fs\n", elapsedTime.Seconds())

	// Prepare environment - start with current environment
	env := os.Environ()
	
	// Add credential-specific environment variables
	for key, value := range creds.Variables {
		// First remove any existing values for this key
		env = filterEnv(env, key)
		// Then add our new value
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}
	
	// Add SESH_ACTIVE=1 to indicate we're in a sesh environment
	env = append(env, "SESH_ACTIVE=1")
	env = append(env, fmt.Sprintf("SESH_SERVICE=%s", serviceName))
	
	// Add expiration time for scripts to check
	if !creds.Expiry.IsZero() {
		expiryStr := fmt.Sprintf("SESH_EXPIRY=%d", creds.Expiry.Unix())
		env = append(env, expiryStr)
		
		// Format human-readable expiry for prompt
		duration := time.Until(creds.Expiry)
		hours := int(duration.Hours())
		minutes := int(duration.Minutes()) % 60
		env = append(env, fmt.Sprintf("SESH_EXPIRY_HUMAN=%dh%dm", hours, minutes))
	}
	
	// Add MFA status
	if creds.MFAAuthenticated {
		env = append(env, "SESH_MFA_AUTHENTICATED=1")
	}

	// Determine which shell to use
	shell := os.Getenv("SHELL")
	if shell == "" {
		// Fallback shells based on platform
		if runtime.GOOS == "windows" {
			shell = "cmd.exe"
		} else {
			shell = "/bin/sh"
		}
	}
	
	// Customize prompt based on shell type
	if isZsh(shell) {
		// ZSH customization
		env = append(env, "SESH_ORIG_PROMPT=$PROMPT")
		env = append(env, "PROMPT=\"%F{cyan}[sesh:%F{green}"+serviceName+"%F{cyan}]%f $PROMPT\"")
	} else if isBash(shell) {
		// Bash customization
		env = append(env, "SESH_ORIG_PS1=$PS1")
		env = append(env, "PS1=\"\\[\\e[36m\\][sesh:\\[\\e[32m\\]"+serviceName+"\\[\\e[36m\\]]\\[\\e[0m\\] $PS1\"")
	} else {
		// Generic prompt for other shells
		env = append(env, "PS1=\"[sesh:"+serviceName+"] $ \"")
	}
	
	// Create the command
	cmd := exec.Command(shell)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = env
	
	// Print helpful message
	fmt.Fprintf(a.Stdout, "\n🔒 Starting secure shell with %s credentials\n", serviceName)
	fmt.Fprintf(a.Stdout, "⏳ Credentials expire at: %s\n", creds.Expiry.Format(time.RFC1123))
	if creds.MFAAuthenticated {
		fmt.Fprintf(a.Stdout, "✅ MFA-authenticated session active\n")
	}
	fmt.Fprintf(a.Stdout, "🚪 Exit the shell to end credential access\n\n")
	
	// Run the shell
	err = cmd.Run()
	
	// Print exit message
	fmt.Fprintf(a.Stdout, "\n🔒 Exited secure shell. Credentials no longer accessible.\n")
	
	return err
}

// Helper functions

// filterEnv removes a specific environment variable from the env list
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

// isBash checks if the shell is bash
func isBash(shell string) bool {
	return shell == "/bin/bash" || shell == "/usr/bin/bash" || shell == "bash"
}

// isZsh checks if the shell is zsh
func isZsh(shell string) bool {
	return shell == "/bin/zsh" || shell == "/usr/bin/zsh" || shell == "zsh"
}