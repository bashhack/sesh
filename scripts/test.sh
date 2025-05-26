#!/bin/bash
set -e

# Run standard tests
echo "🧪 Running unit tests..."
go test -v ./...

# Run tests with coverage
echo ""
echo "📊 Generating test coverage..."
go test -coverprofile=coverage.txt ./...

# Filter out mocks, testutil, scripts, and interface-only files
echo "Filtering coverage report..."
grep -v "testutil\|mock\|provider/interfaces.go\|scripts/" coverage.txt > coverage.filtered.txt || true
go tool cover -func=coverage.filtered.txt | grep -v "testutil\|mock\|provider/interfaces.go\|scripts/" || true
rm -f coverage.filtered.txt

echo ""
echo "✅ All tests completed successfully."