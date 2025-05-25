#!/bin/bash
set -e

# Check if SKIP_KEYCHAIN_TESTS is already set, if not default to empty (allow keychain tests)
# This allows the Makefile to control the default behavior
SKIP_KEYCHAIN_TESTS=${SKIP_KEYCHAIN_TESTS:-}

# Run standard tests
echo "🧪 Running unit tests..."
if [ -n "$SKIP_KEYCHAIN_TESTS" ]; then
    echo "   (Keychain integration tests disabled)"
else
    echo "   (Including keychain integration tests)"
fi
go test -v ./...

# Run tests with coverage
echo ""
echo "📊 Generating test coverage..."
go test -coverprofile=coverage.txt ./...
go tool cover -func=coverage.txt

echo ""
echo "✅ All tests completed successfully."