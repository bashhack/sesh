#!/bin/sh

# This script adds sesh shell integration

sesh() {
  if [ $# -eq 0 ]; then
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
    case "$1" in
    --help | -h | --setup | --version | -v)
      command sesh "$@"
      ;;
    --profile | -p | --serial | -s | --keychain-user | --keychain-name)
      # These are credential flags that need eval
      echo "🔐 Activating AWS session with MFA..." >&2
      eval "$(command sesh "$@")"

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
      command sesh "$@"
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
  - Running 'sesh --profile dev' will activate with a specific profile
  - All other sesh commands work normally

To deactivate this integration for the current session:
  unset -f sesh
EOF
}
