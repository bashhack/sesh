#!/bin/bash

set -e

# Variables
VERSION=${1:-latest}
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ]; then
  ARCH="amd64"
elif [ "$ARCH" = "arm64" ]; then
  ARCH="arm64"
else
  echo "❌ Unsupported architecture: $ARCH"
  exit 1
fi

if [ "$OS" != "darwin" ]; then
  echo "❌ Sorry, only macOS is currently supported"
  exit 1
fi

# Determine install directory - prefer /usr/local/bin, fall back to ~/.local/bin
INSTALL_DIR="/usr/local/bin"
if [ ! -w "$INSTALL_DIR" ]; then
  INSTALL_DIR="$HOME/.local/bin"
  mkdir -p "$INSTALL_DIR"
  echo "📋 Installing to $INSTALL_DIR (no admin privileges required)"
  
  # Check if the directory is in PATH
  if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    echo "⚠️ Please add ~/.local/bin to your PATH:"
    echo "   export PATH=\"\$HOME/.local/bin:\$PATH\""
  fi
else
  echo "📋 Installing to $INSTALL_DIR"
fi

# Download the binary
if [ "$VERSION" = "latest" ]; then
  DOWNLOAD_URL="https://github.com/bashhack/sesh/releases/latest/download/sesh_${OS}_${ARCH}.tar.gz"
else
  DOWNLOAD_URL="https://github.com/bashhack/sesh/releases/download/${VERSION}/sesh_${OS}_${ARCH}.tar.gz"
fi

echo "⬇️ Downloading sesh from $DOWNLOAD_URL..."
TMP_DIR=$(mktemp -d)
curl -sL "$DOWNLOAD_URL" | tar -xz -C "$TMP_DIR"
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

# Create directories for shell integration
SHARE_DIR="/usr/local/share/sesh"
if [ ! -w "/usr/local/share" ]; then
  SHARE_DIR="$HOME/.local/share/sesh"
fi
mkdir -p "$SHARE_DIR"

# Add to PATH automatically if using zsh and installed to ~/.local/bin
if [[ "$SHELL" == */zsh && "$INSTALL_DIR" == "$HOME/.local/bin" && ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
  echo "# Adding ~/.local/bin to PATH for sesh" >> ~/.zshrc
  echo "export PATH=\"\$HOME/.local/bin:\$PATH\"" >> ~/.zshrc
  echo "✅ Added ~/.local/bin to PATH in ~/.zshrc"
fi

# Download shell integration
echo "⬇️ Installing shell integration..."
curl -sSL "https://raw.githubusercontent.com/bashhack/sesh/main/shell/sesh.sh" -o "$SHARE_DIR/sesh.sh"
chmod +x "$SHARE_DIR/sesh.sh"

echo ""
echo "🚀 Get started with:"
echo "  sesh --setup    # First-time setup"
echo ""
echo "✨ To enable the shell integration (recommended):"
echo "  1. Add this line to your ~/.bashrc or ~/.zshrc:"
echo "     source \"$SHARE_DIR/sesh.sh\""
echo "  2. Restart your terminal or run: source \"$SHARE_DIR/sesh.sh\""
echo "  3. Then simply use: sesh"
