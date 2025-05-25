#!/bin/bash
# This script helps identify which test is triggering keychain access

echo "🔍 Running tests one package at a time to identify keychain access..."
echo "   Watch for macOS keychain prompts and note which package is running"
echo ""

packages=(
    "./sesh/cmd/sesh"
    "./internal/keychain"
    "./internal/aws"
    "./internal/totp"
    "./internal/provider/aws"
    "./internal/provider/totp"
    "./internal/setup"
    "./internal/password"
)

for pkg in "${packages[@]}"; do
    echo "===================================="
    echo "Testing package: $pkg"
    echo "===================================="
    go test -v "$pkg" -count=1
    
    echo ""
    echo "Press Enter to continue to next package..."
    read -r
done

echo "✅ Test isolation complete"