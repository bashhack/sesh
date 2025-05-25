#!/bin/bash
# Test each test function individually to find the one causing keychain access

cd /Users/marcalvarez/Development/Personal/sesh

echo "Testing each function individually..."
echo "If you see a keychain prompt, note the test name above it"
echo ""

# Get all test functions
tests=$(go test -list . ./internal/keychain 2>/dev/null | grep "^Test" | grep -v "Integration")

for test in $tests; do
    echo "========================================"
    echo "TESTING: $test"
    echo "========================================"
    
    # Run just this one test
    SKIP_KEYCHAIN_TESTS=true go test ./internal/keychain -run "^${test}$" -count=1 -v
    
    # Give time to see if keychain prompt appears
    sleep 1
done