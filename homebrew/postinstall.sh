#!/bin/bash

# Check if sesh binary is properly installed
if ! command -v sesh &> /dev/null; then
  echo "❌ Error: sesh binary not found in PATH"
  echo "Please make sure your Homebrew installation was successful."
  exit 1
fi

# Check if AWS CLI is installed
if ! command -v aws &> /dev/null; then
  echo "⚠️  Warning: AWS CLI not found"
  echo "sesh requires the AWS CLI to function properly."
  echo "Please install it using: brew install awscli"
fi

# All checks passed
echo "✅ sesh is properly installed!"
echo "To get started, run: sesh --setup"
echo "Then use: eval \"\$(sesh)\""