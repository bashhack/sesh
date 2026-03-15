#!/bin/bash

set -e

# Variables
VERSION=${1:-latest}
ARCH=$(uname -m)

if [ "$(uname -s)" != "Darwin" ]; then
  echo "❌ Sorry, only macOS is currently supported"
  exit 1
fi

if [ "$ARCH" != "x86_64" ] && [ "$ARCH" != "arm64" ]; then
  echo "❌ Unsupported architecture: $ARCH"
  exit 1
fi

# Install directory is always ~/.local/bin
INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"
echo "📋 Installing to $INSTALL_DIR (standard user location)"

# Add to PATH if needed
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
  SHELL_RC=""
  if [[ "$SHELL" == */zsh ]]; then
    SHELL_RC="$HOME/.zshrc"
  elif [[ "$SHELL" == */bash ]]; then
    SHELL_RC="$HOME/.bashrc"
  fi

  if [ -n "$SHELL_RC" ]; then
    if grep -q '/.local/bin' "$SHELL_RC" 2>/dev/null; then
      echo "ℹ️ ~/.local/bin is already in $(basename "$SHELL_RC") — open a new terminal to pick it up"
    else
      printf "⚠️ ~/.local/bin is not in your PATH. Add it to %s? [Y/n] " "$(basename "$SHELL_RC")"
      read -r REPLY
      if [[ "$REPLY" =~ ^[Nn]$ ]]; then
        echo "   To add it manually:"
        echo "   export PATH=\"\$HOME/.local/bin:\$PATH\""
      else
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$SHELL_RC"
        echo "✅ Added ~/.local/bin to PATH in $(basename "$SHELL_RC")"
        echo "   Run 'source $SHELL_RC' or open a new terminal to use sesh"
      fi
    fi
  else
    echo "⚠️ Please add ~/.local/bin to your PATH:"
    echo "   export PATH=\"\$HOME/.local/bin:\$PATH\""
  fi
fi

# Download the binary
if [ "$VERSION" = "latest" ]; then
  DOWNLOAD_URL="https://github.com/bashhack/sesh/releases/latest/download/sesh_Darwin_${ARCH}.zip"
else
  DOWNLOAD_URL="https://github.com/bashhack/sesh/releases/download/${VERSION}/sesh_Darwin_${ARCH}.zip"
fi

echo "⬇️ Downloading sesh from $DOWNLOAD_URL..."
TMP_DIR=$(mktemp -d)
if ! curl -sfL -o "$TMP_DIR/sesh.zip" "$DOWNLOAD_URL"; then
  echo "❌ Download failed. Check that the version exists at:"
  echo "   https://github.com/bashhack/sesh/releases"
  rm -rf "$TMP_DIR"
  exit 1
fi
unzip -q "$TMP_DIR/sesh.zip" -d "$TMP_DIR"
chmod +x "$TMP_DIR/sesh"
mv "$TMP_DIR/sesh" "$INSTALL_DIR/sesh"
rm -rf "$TMP_DIR"

# Verify installation
echo "✅ Installation completed!"
"$INSTALL_DIR/sesh" --version

# Check for AWS CLI
if ! command -v aws &>/dev/null; then
  echo "⚠️ Warning: AWS CLI not found"
  echo "sesh requires the AWS CLI to function properly."
  echo "Please install it: https://aws.amazon.com/cli/"
fi

echo ""
echo "🚀 To get started, run:"
echo "   sesh --help     # Show available commands and options"
