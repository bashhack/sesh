package aws

var SubshellFunctions = `
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

Exit Options:
  exit           Type 'exit' to leave the secure subshell
  Ctrl+D         Press Ctrl+D to send EOF and exit

Environment Variables:
  AWS_ACCESS_KEY_ID     - Your temporary AWS access key
  AWS_SECRET_ACCESS_KEY - Your temporary AWS secret key
  AWS_SESSION_TOKEN     - Your temporary AWS session token
EOF
}

# Welcome message
echo "🔐 Secure shell with aws credentials activated. Type 'sesh_help' for more information."
`
