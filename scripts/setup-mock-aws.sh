#!/bin/bash
# setup-mock-aws.sh - Sets up mock AWS CLI for testing sesh

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
MOCK_BIN_DIR="$SCRIPT_DIR/mock-bin"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}Setting up Mock AWS CLI for sesh testing${NC}"
echo

# Create mock bin directory
mkdir -p "$MOCK_BIN_DIR"

# Build the mock AWS CLI
echo -e "${BLUE}Building mock AWS CLI...${NC}"
cd "$SCRIPT_DIR"
go build -o "$MOCK_BIN_DIR/aws" mock-aws-cli.go

# Make it executable
chmod +x "$MOCK_BIN_DIR/aws"

echo -e "${GREEN}✓ Mock AWS CLI built successfully${NC}"
echo

# Show usage instructions
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}Usage Instructions:${NC}"
echo
echo -e "${BLUE}1. Add mock AWS to your PATH (in current shell):${NC}"
echo -e "   export PATH=\"$MOCK_BIN_DIR:\$PATH\""
echo
echo -e "${BLUE}2. Verify mock AWS is being used:${NC}"
echo -e "   which aws  # Should show: $MOCK_BIN_DIR/aws"
echo
echo -e "${BLUE}3. Test sesh AWS setup flow:${NC}"
echo -e "   sesh --service aws --setup"
echo
echo -e "${BLUE}4. When you need to scan a QR code:${NC}"
echo -e "   # In another terminal, run the mock TOTP service:"
echo -e "   go run $SCRIPT_DIR/mock-totp-service.go AWS"
echo
echo -e "${BLUE}5. Test sesh AWS credential generation:${NC}"
echo -e "   sesh --service aws"
echo -e "   sesh --service aws --clip"
echo
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo
echo -e "${GREEN}Advanced Testing:${NC}"
echo
echo -e "• Test error scenarios:"
echo -e "  export MOCK_AWS_FAIL=true    # Simulate expired token"
echo -e "  export MOCK_AWS_NO_MFA=true  # Simulate no MFA devices"
echo
echo -e "• Reset to normal:"
echo -e "  unset MOCK_AWS_FAIL MOCK_AWS_NO_MFA"
echo
echo -e "${RED}Note: Remember to remove the mock from PATH when done testing!${NC}"
echo -e "      export PATH=\${PATH#$MOCK_BIN_DIR:}"