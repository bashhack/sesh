#!/bin/bash
#
# mock-totp-service.sh - Simulates an external TOTP service for testing sesh
#
# Usage:
#   ./mock-totp-service.sh [SERVICE_NAME] [ACCOUNT_NAME]
#
# Examples:
#   ./mock-totp-service.sh                    # Creates TestService with testuser@example.com
#   ./mock-totp-service.sh GitHub             # Creates GitHub with testuser@example.com
#   ./mock-totp-service.sh Datadog ops@company.com  # Creates Datadog with ops@company.com
#
# This script generates a random TOTP secret and displays setup instructions
# for testing sesh's TOTP functionality without needing real service accounts.

set -euo pipefail

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Generate a random base32 secret
SECRET=$(openssl rand -hex 16 | xxd -r -p | base32 | tr -d '=' | tr '[:lower:]' '[:upper:]')

# Service details (customize these to simulate different services)
SERVICE_NAME="${1:-TestService}"
ACCOUNT_NAME="${2:-testuser@example.com}"
ISSUER="$SERVICE_NAME"

# Build the TOTP URI
URI="otpauth://totp/${ISSUER}:${ACCOUNT_NAME}?secret=${SECRET}&issuer=${ISSUER}"

echo -e "${GREEN}=== Mock TOTP Service: $SERVICE_NAME ===${NC}"
echo
echo -e "${BLUE}Account:${NC} $ACCOUNT_NAME"
echo -e "${BLUE}Secret:${NC}  $SECRET"
echo
echo -e "${YELLOW}QR Code:${NC}"

# Generate QR code if qrencode is available
if command -v qrencode &> /dev/null; then
    qrencode -t ANSIUTF8 "$URI"
else
    echo "Install qrencode to see QR code: brew install qrencode"
    echo "URI: $URI"
fi

echo
echo -e "${GREEN}To set up in sesh:${NC}"
echo -e "1. Run: ${YELLOW}sesh --service totp --setup${NC}"
echo -e "2. When prompted for service name, enter: ${YELLOW}$SERVICE_NAME${NC}"
echo -e "3. When prompted for secret, enter: ${YELLOW}$SECRET${NC}"
echo
echo -e "${GREEN}To test:${NC}"
echo -e "Run: ${YELLOW}sesh --service totp --service-name $SERVICE_NAME${NC}"
echo -e "  or: ${YELLOW}sesh --service totp --service-name $SERVICE_NAME --clip${NC} (copy to clipboard)"