#!/bin/bash
set -e

# Run standard tests
echo "🧪 Running unit tests..."
go test -v ./...

# Run tests with coverage
echo "📊 Generating test coverage..."
go test -coverprofile=coverage.txt ./...
go tool cover -func=coverage.txt

# Run more detailed tests if requested
if [ "$1" == "--full" ]; then
    echo "🔍 Running integration tests..."
    RUN_INTEGRATION_TESTS=1 go test -v ./...
    
    echo "🔬 Running experimental tests..."
    RUN_EXPERIMENTAL_TESTS=1 go test -v ./...
fi

echo "✅ All tests completed successfully."