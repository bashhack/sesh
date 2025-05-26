#!/bin/bash
set -e

# Run standard tests
echo "🧪 Running unit tests..."
go test -v ./...

# Run tests with coverage
echo ""
echo "📊 Generating test coverage..."
go test -coverprofile=coverage.txt ./...
go tool cover -func=coverage.txt

echo ""
echo "✅ All tests completed successfully."