#!/bin/sh

# Shell integration for sesh with subshell support
# This script provides convenience functions for working with sesh

# Main sesh function that handles argument parsing
sesh() {
  # Allow double-dash arguments for compatibility
  args=()
  while [ $# -gt 0 ]; do
    arg="$1"
    shift

    # Check if the argument starts with double dash and convert to single dash if needed
    if echo "$arg" | grep -q "^--"; then
      arg=$(echo "$arg" | sed 's/^--/-/')
    fi
    args+=("$arg")
  done

  # If we're already in a sesh subshell, warn the user
  if [ -n "$SESH_ACTIVE" ]; then
    echo "⚠️ You are already in a sesh environment for $SESH_SERVICE" >&2
    echo "⏳ Current credentials expire in $SESH_EXPIRY_HUMAN" >&2
    echo "💡 Type 'exit' to leave this shell before starting a new one" >&2
    return 1
  fi

  # Pass through to the actual sesh command
  if [ ${#args[@]} -eq 0 ]; then
    # No arguments defaults to AWS with subshell
    command sesh -service aws
  else
    command sesh "${args[@]}"
  fi
}

# Display usage information for shell integration
sesh_info() {
  cat <<EOF
🛠️ sesh shell integration is active!

Usage:
  sesh                    Launch a secure subshell with AWS credentials
  sesh -profile dev       Launch with specific AWS profile
  sesh -service totp      Generate TOTP codes (standard output)
  sesh -clip              Copy AWS MFA code to clipboard
  sesh -help              Show help information

Security Features:
  - AWS credentials are isolated in a subshell environment
  - Credentials automatically removed when you exit the subshell
  - Clear visual indication when using AWS credentials
  - Protection from processes in parent shell

To deactivate shell integration for current session:
  unset -f sesh sesh_info
EOF
}

# Function to show current sesh status when in a subshell
sesh_status() {
  if [ -n "$SESH_ACTIVE" ]; then
    echo "🔒 Active sesh session for service: $SESH_SERVICE"
    
    if [ -n "$SESH_EXPIRY" ]; then
      # Calculate time remaining
      now=$(date +%s)
      expiry=$SESH_EXPIRY
      remaining=$((expiry - now))
      
      if [ $remaining -le 0 ]; then
        echo "⚠️ Credentials have EXPIRED!"
      else
        hours=$((remaining / 3600))
        minutes=$(( (remaining % 3600) / 60 ))
        seconds=$((remaining % 60))
        echo "⏳ Credentials expire in: ${hours}h ${minutes}m ${seconds}s"
      fi
    fi
    
    if [ -n "$SESH_MFA_AUTHENTICATED" ]; then
      echo "✅ MFA authentication is active"
    fi
    
    if [ "$SESH_SERVICE" = "aws" ]; then
      echo ""
      echo "AWS Environment Variables:"
      env | grep -E "^AWS_(ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN)" | sed 's/=.*$/=***/'
    fi
  else
    echo "❌ Not currently in a sesh environment"
  fi
}

# Initialize shell integration
if [ -n "$BASH_VERSION" ] || [ -n "$ZSH_VERSION" ]; then
  # In Bash or Zsh
  echo "🔑 sesh shell integration loaded. Type 'sesh_info' for usage information." >&2
else
  # Generic shell - give minimal feedback
  echo "🔑 sesh shell integration loaded." >&2
fi