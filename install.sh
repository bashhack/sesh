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

# Install directory is always ~/.local/bin
INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"
echo "📋 Installing to $INSTALL_DIR (standard user location)"

# Check if the directory is in PATH
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
  echo "⚠️ Please add ~/.local/bin to your PATH:"
  echo "   export PATH=\"\$HOME/.local/bin:\$PATH\""
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
SHARE_DIR="$HOME/.local/share/sesh"
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
echo "✨ Shell integration setup:"
echo "Where would you like to add shell integration?"
echo "  1) ~/.zshrc"
echo "  2) ~/.bashrc"
echo "  3) Custom path"
echo "  4) Skip (I'll add it manually)"

read -p "Enter selection [1-4]: " SELECTION

if [ "$SELECTION" = "1" ]; then
  PROFILE="$HOME/.zshrc"
elif [ "$SELECTION" = "2" ]; then
  PROFILE="$HOME/.bashrc"
elif [ "$SELECTION" = "3" ]; then
  read -p "Enter the full path to your shell profile: " CUSTOM_PROFILE
  PROFILE="$CUSTOM_PROFILE"
else
  PROFILE=""
fi

if [ "$PROFILE" != "" ]; then
  if [ -f "$PROFILE" ]; then
    if ! grep -q "Added by sesh shell/install" "$PROFILE"; then
      echo "" >> "$PROFILE"
      echo "# Added by sesh shell/install" >> "$PROFILE"
      echo "source \"$SHARE_DIR/sesh.sh\"" >> "$PROFILE"
      echo "✅ Shell integration added to $PROFILE"
    else
      echo "ℹ️ Shell integration already exists in $PROFILE"
    fi
  else
    echo "⚠️ Profile file $PROFILE does not exist"
    echo "🔐 To enable shell integration manually, add this line to your profile:"
    echo "   source \"$SHARE_DIR/sesh.sh\""
  fi
else
  echo "🔐 To enable shell integration manually, add this line to your profile:"
  echo "   source \"$SHARE_DIR/sesh.sh\""
fi

echo ""
echo "🚀 To get started, run:"
echo "   sesh --setup    # First-time setup"
echo "   sesh           # Generate credentials"
