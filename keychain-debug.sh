#!/bin/bash

USERNAME=$(whoami)
echo "Analyzing keychain entries related to sesh..."

echo "Current user: $USERNAME"
echo "Current executable path: $(which sesh)"

echo "=== Keychain Entries ==="
security dump-keychain | grep -A 5 -B 5 sesh

echo "=== Trying to access sesh-mfa ==="
security find-generic-password -a "$USERNAME" -s "sesh-mfa" 2>&1 | grep -v password

echo "=== Access Control Lists ==="
# Note: This command will prompt for keychain access
security dump-keychain -d | grep -A 20 -B 5 "sesh-mfa" | grep -A 10 "Access"