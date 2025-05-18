package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// LaunchSubshell launches a new shell with credentials loaded
func (a *App) LaunchSubshell(serviceName string) error {
	// Get provider and credentials
	p, err := a.Registry.GetProvider(serviceName)
	if err != nil {
		return fmt.Errorf("provider not found: %w", err)
	}

	creds, err := p.GetCredentials()
	if err != nil {
		return fmt.Errorf("failed to generate credentials: %w", err)
	}

	// Create environment with credentials
	env := os.Environ()

	// Add credential variables to environment
	for key, value := range creds.Variables {
		env = filterEnv(env, key)
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}

	// Add basic SESH variables
	env = append(env, "SESH_ACTIVE=1")
	env = append(env, fmt.Sprintf("SESH_SERVICE=%s", serviceName))
	env = append(env, "SESH_DISABLE_INTEGRATION=1")

	// Add session timing information
	env = append(env, fmt.Sprintf("SESH_START_TIME=%d", time.Now().Unix()))
	if !creds.Expiry.IsZero() {
		env = append(env, fmt.Sprintf("SESH_EXPIRY=%d", creds.Expiry.Unix()))
		env = append(env, fmt.Sprintf("SESH_TOTAL_DURATION=%d", creds.Expiry.Unix()-time.Now().Unix()))
	}

	// Determine which shell to use
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}

	// Create common shell functions for all shells
	commonFunctions := fmt.Sprintf(`
# Function to show current sesh status
sesh_status() {
  echo "🔒 Active sesh session for service: $SESH_SERVICE"
  
  if [ -n "$SESH_EXPIRY" ]; then
    # Calculate time remaining
    now=$(date +%%s)
    expiry=$SESH_EXPIRY
    remaining=$((expiry - now))
    
    if [ $remaining -le 0 ]; then
      echo "⚠️ Credentials have EXPIRED!"
    else
      hours=$((remaining / 3600))
      minutes=$(( (remaining %% 3600) / 60 ))
      seconds=$((remaining %% 60))
      
      # Show remaining time
      echo "⏳ Credentials expire in: ${hours}h ${minutes}m ${seconds}s"
      
      # Calculate percentage remaining if we have total duration
      if [ -n "$SESH_TOTAL_DURATION" ] && [ $SESH_TOTAL_DURATION -gt 0 ]; then
        percent_remaining=$(( (remaining * 100) / SESH_TOTAL_DURATION ))
        progress_bar="["
        for i in {1..20}; do
          if [ $i -le $((percent_remaining / 5)) ]; then
            progress_bar="${progress_bar}█"
          else
            progress_bar="${progress_bar}░"
          fi
        done
        progress_bar="${progress_bar}] ${percent_remaining}%%"
        echo "   Session progress: $progress_bar"
      fi
    fi
  fi
  
  # Check AWS credentials
  if [ "$SESH_SERVICE" = "aws" ]; then
    echo ""
    echo "AWS Environment Variables:"
    [ -n "$AWS_ACCESS_KEY_ID" ] && echo "AWS_ACCESS_KEY_ID=***"
    [ -n "$AWS_SECRET_ACCESS_KEY" ] && echo "AWS_SECRET_ACCESS_KEY=***"
    [ -n "$AWS_SESSION_TOKEN" ] && echo "AWS_SESSION_TOKEN=***"
    
    echo ""
    echo "Testing AWS credentials..."
    if aws sts get-caller-identity >/dev/null 2>&1; then
      echo "✅ AWS credentials are working correctly"
      echo ""
      echo "Your identity:"
      aws sts get-caller-identity --query "Arn" --output text
    else
      echo "❌ AWS credentials test failed"
    fi
  fi
}

# Shortcut to verify AWS credentials
verify_aws() {
  if [ "$SESH_SERVICE" != "aws" ]; then
    echo "❌ Not in an AWS sesh environment"
    return 1
  fi
  
  echo "Testing AWS MFA authentication..."
  
  # Try to access IAM information (typically requires MFA)
  if aws iam list-account-aliases >/dev/null 2>&1; then
    echo "✅ AWS MFA authentication VERIFIED"
    echo "Successfully accessed IAM data that requires MFA"
    return 0
  else
    echo "❓ AWS MFA status uncertain"
    echo "Could not access IAM data - this could be due to IAM permissions rather than MFA status"
    
    # Show the caller identity anyway
    echo ""
    echo "Current identity:"
    aws sts get-caller-identity --query "Arn" --output text
    return 1
  fi
}

# Help command
sesh_help() {
  cat <<EOF
🔒 sesh Secure Subshell

You are in a secure environment with isolated AWS credentials.
These credentials will be automatically removed when you exit.

Commands:
  sesh_status    Show status and verify credentials
  verify_aws     Test if AWS MFA authentication is working
  exit           Exit the secure subshell and remove credentials

Environment Variables:
  AWS_ACCESS_KEY_ID     - Your temporary AWS access key
  AWS_SECRET_ACCESS_KEY - Your temporary AWS secret key
  AWS_SESSION_TOKEN     - Your temporary AWS session token
EOF
}

# Welcome message
echo "🔐 Secure shell with %s credentials activated. Type 'sesh_help' for more information."
`, serviceName)

	// Handle shell-specific init customization
	var cmd *exec.Cmd

	switch {
	case shell == "/bin/zsh" || filepath.Base(shell) == "zsh":
		// Create a temporary ZDOTDIR for zsh
		tmpDir, err := os.MkdirTemp("", "sesh_zsh")
		if err != nil {
			return fmt.Errorf("failed to create temp dir for zsh: %w", err)
		}
		zshrc := filepath.Join(tmpDir, ".zshrc")

		// Construct zsh init script with common functions
		zshrcContent := fmt.Sprintf(`
export SESH_ACTIVE=1
export SESH_SERVICE=%q
PROMPT="(sesh:%s) ${PROMPT}"

%s
`, serviceName, serviceName, commonFunctions)

		if writeErr := os.WriteFile(zshrc, []byte(zshrcContent), 0644); writeErr != nil {
			return fmt.Errorf("failed to write temp zshrc: %w", writeErr)
		}
		env = append(env, fmt.Sprintf("ZDOTDIR=%s", tmpDir))
		cmd = exec.Command(shell)

	case shell == "/bin/bash" || filepath.Base(shell) == "bash":
		// Create a temporary rcfile for bash
		tmpFile, err := os.CreateTemp("", "sesh_bashrc")
		if err != nil {
			return fmt.Errorf("failed to create temp bashrc: %w", err)
		}
		defer tmpFile.Close()

		// Construct bash init script with common functions
		bashrcContent := fmt.Sprintf(`
export SESH_ACTIVE=1
export SESH_SERVICE=%q
PS1="(sesh:%s) $PS1"

%s
`, serviceName, serviceName, commonFunctions)

		if _, writeErr := tmpFile.WriteString(bashrcContent); writeErr != nil {
			return fmt.Errorf("failed to write temp bashrc: %w", writeErr)
		}
		cmd = exec.Command(shell, "--rcfile", tmpFile.Name())

	default:
		// fallback shell - create a basic script file to define functions
		tmpFile, err := os.CreateTemp("", "sesh_shellrc")
		if err != nil {
			return fmt.Errorf("failed to create temp shellrc: %w", err)
		}
		defer tmpFile.Close()

		// Construct simplified version for other shells
		shellrcContent := fmt.Sprintf(`
export SESH_ACTIVE=1
export SESH_SERVICE=%q

# Simple subset of common functions for basic shells
sesh_status() {
  echo "🔒 Active sesh session for service: $SESH_SERVICE"
  
  if [ -n "$SESH_EXPIRY" ]; then
    now=$(date +%%s)
    expiry=$SESH_EXPIRY
    remaining=$((expiry - now))
    
    if [ $remaining -le 0 ]; then
      echo "⚠️ Credentials have EXPIRED!"
    else
      hours=$((remaining / 3600))
      minutes=$(( (remaining %% 3600) / 60 ))
      seconds=$((remaining %% 60))
      echo "⏳ Credentials expire in: ${hours}h ${minutes}m ${seconds}s"
    fi
  fi
  
  # Check AWS credentials
  if [ "$SESH_SERVICE" = "aws" ]; then
    echo ""
    echo "AWS Environment Variables set"
  fi
}

verify_aws() {
  aws sts get-caller-identity --query "Arn" --output text
}

echo "🔐 Secure shell with %s credentials activated"
`, serviceName, serviceName)

		if _, writeErr := tmpFile.WriteString(shellrcContent); writeErr != nil {
			return fmt.Errorf("failed to write temp shellrc: %w", writeErr)
		}

		// Set environment to show the prompt
		env = append(env, fmt.Sprintf("PS1=(sesh:%s) $ ", serviceName))
		env = append(env, fmt.Sprintf("ENV=%s", tmpFile.Name())) // For sh shells

		cmd = exec.Command(shell)
	}

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = env

	fmt.Fprintf(a.Stdout, "Starting secure shell with %s credentials\n", serviceName)
	err = cmd.Run()
	fmt.Fprintf(a.Stdout, "Exited secure shell\n")
	
	// Handle different exit scenarios gracefully
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				// Check if terminated by signal
				if status.Signaled() {
					sig := status.Signal()
					if sig == syscall.SIGINT {
						// Treat Ctrl+C as a normal exit
						return nil
					}
					// For other signals, provide context but no error indicator
					fmt.Fprintf(a.Stderr, "Shell session ended: %s\n", explainSignal(sig))
					return nil
				} else if status.ExitStatus() == 130 {
					// Exit 130 is a special case - it's SIGINT, but reported as an exit code
					// This happens in some terminals and shells
					return nil
				} else if status.ExitStatus() != 0 {
					// Only report truly unexpected exit codes
					fmt.Fprintf(a.Stderr, "Shell exited with code %d\n", status.ExitStatus())
				}
			}
			// Don't return an error for common shell exit scenarios
			return nil
		}
		// Only return truly unexpected errors
		return fmt.Errorf("subshell encountered an unexpected error: %w", err)
	}

	return nil
}

// explainSignal provides a user-friendly description of common signals
func explainSignal(sig syscall.Signal) string {
	switch sig {
	case syscall.SIGINT:
		return "interrupted (Ctrl+C)"
	case syscall.SIGTERM:
		return "terminated by system"
	case syscall.SIGHUP:
		return "terminal closed"
	case syscall.SIGQUIT:
		return "quit (Ctrl+\\)"
	default:
		return fmt.Sprintf("signal %d", sig)
	}
}

// Helper function to filter environment variables
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
