package aws

import "github.com/bashhack/sesh/internal/subshell"

var _ subshell.ShellCustomizer = (*AWSShellCustomizer)(nil)

var (
	// SubshellFunctions contains the helper function for the AWS subshell integration
	SubshellFunctions = `
# Function to show current sesh status
sesh_status() {
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

      # Show remaining time
      echo "⏳ Credentials expire in: ${hours}h ${minutes}m ${seconds}s"

      # Calculate percentage remaining if we have total duration
      if [ -n "$SESH_TOTAL_DURATION" ] && [ $SESH_TOTAL_DURATION -gt 0 ]; then
        percent_remaining=$(( (remaining * 100) / SESH_TOTAL_DURATION ))
        progress_bar="["
        i=1
        while [ $i -le 20 ]; do
          if [ $i -le $((percent_remaining / 5)) ]; then
            progress_bar="${progress_bar}█"
          else
            progress_bar="${progress_bar}░"
          fi
          i=$((i + 1))
        done
        progress_bar="${progress_bar}] ${percent_remaining}%"
        echo "   Session progress: $progress_bar"
      fi
    fi
  fi

  # Check AWS credentials
  if [ "$SESH_SERVICE" = "aws" ]; then
    echo ""
    if [ -z "$AWS_ACCESS_KEY_ID" ]; then
      echo "Signed in through the profile ${AWS_PROFILE:-default}: the AWS CLI keeps its credentials fresh."
    else
      echo "AWS Environment Variables:"
      [ -n "$AWS_ACCESS_KEY_ID" ] && echo "AWS_ACCESS_KEY_ID=***"
      [ -n "$AWS_SECRET_ACCESS_KEY" ] && echo "AWS_SECRET_ACCESS_KEY=***"
      [ -n "$AWS_SESSION_TOKEN" ] && echo "AWS_SESSION_TOKEN=***"
    fi

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

# verify_aws checks the session's credentials with AWS, and says who
# they sign in as. sesh got the session with an MFA code, so it's an MFA
# session for as long as it lasts.
verify_aws() {
  if [ "$SESH_SERVICE" != "aws" ]; then
    echo "❌ Not in an AWS sesh environment"
    return 1
  fi
  if identity=$(aws sts get-caller-identity --query Arn --output text 2>&1); then
    echo "✅ The credentials work: signed in as $identity, with the MFA session sesh started"
  else
    echo "❌ AWS didn't accept the credentials: $identity"
    return 1
  fi
}

# Help command
sesh_help() {
  cat <<EOF
🔒 sesh: a shell with an AWS session

This shell has the session's credentials in its environment, on top of
your own shell setup. They leave with the shell when it exits; AWS still
accepts them until they expire.

Commands:
  sesh_status    How long the credentials have, and who they sign in as
  verify_aws     Check the credentials work, and who they sign in as

Leave with exit, or Ctrl-D.

Environment variables:
  AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN   the session's credentials
  SESH_ACTIVE, SESH_SERVICE, SESH_EXPIRY, SESH_TOTAL_DURATION    what this shell is, and until when
EOF
}

# Welcome message
echo "🔐 Secure shell with aws credentials activated. Type 'sesh_help' for more information."
`
)

// AWSShellCustomizer is what sesh aws adds to the shell it opens.
type AWSShellCustomizer struct{}

// Functions is the helper commands, and the line saying the shell is ready.
func (c *AWSShellCustomizer) Functions() string {
	return SubshellFunctions
}

// PromptPrefix is (sesh:aws), before the user's own prompt.
func (c *AWSShellCustomizer) PromptPrefix() string {
	return "(sesh:aws) "
}

// NewCustomizer creates a new AWS shell customizer
func NewCustomizer() *AWSShellCustomizer {
	return &AWSShellCustomizer{}
}
