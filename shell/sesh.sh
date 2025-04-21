#!/bin/sh

# This script adds sesh shell integration with argument conversion support

sesh() {
  # Convert double-dash arguments to single-dash
  args=()
  while [ $# -gt 0 ]; do
    arg="$1"
    shift

    # Check if the argument starts with double dash
    if echo "$arg" | grep -q "^--"; then
      # Replace -- with - at the beginning
      arg=$(echo "$arg" | sed 's/^--/-/')
    fi
    args+=("$arg")
  done

  # Execute with converted arguments
  if [ ${#args[@]} -eq 0 ]; then
    # No arguments - activate AWS session
    echo "🔐 Activating AWS session with MFA..." >&2
    eval "$(command sesh)"

    if [ $? -eq 0 ]; then
      echo "✅ AWS session activated" >&2
      return 0
    else
      echo "❌ Failed to activate AWS session" >&2
      return 1
    fi
  else
    # Check first argument for special flags
    case "${args[0]}" in
    -help | -h | -setup | -version | -v)
      command sesh "${args[@]}"
      ;;
    -profile | -p | -serial | -s | -keychain-user | -keychain-name)
      # These are credential flags that need eval
      echo "🔐 Activating AWS session with MFA..." >&2
      eval "$(command sesh "${args[@]}")"

      if [ $? -eq 0 ]; then
        echo "✅ AWS session activated" >&2
        return 0
      else
        echo "❌ Failed to activate AWS session" >&2
        return 1
      fi
      ;;
    *)
      # For any other command, just pass through to sesh
      command sesh "${args[@]}"
      ;;
    esac
  fi
}

# Help function available if needed, but not displayed automatically
sesh_info() {
  cat <<EOF
🛠️ sesh shell integration is active!

Now you can simply type 'sesh' instead of 'eval "\$(sesh)"'
  - Running 'sesh' will activate AWS credentials
  - Running 'sesh --profile dev' will activate with a specific profile (both --flag and -flag formats work)
  - All other sesh commands work normally

Available command formats:
  - Supports both GNU-style long options (--flag) and Go-style options (-flag)
  - Example: 'sesh --service totp --list' and 'sesh -service totp -list' both work

To deactivate this integration for the current session:
  unset -f sesh
EOF
}
