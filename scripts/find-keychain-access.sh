#!/bin/bash
# Script to find which test is triggering keychain access

cd /Users/marcalvarez/Development/Personal/sesh

echo "Finding test that triggers keychain access..."
echo "Watch for the keychain prompt and note which test is running"
echo ""

# Get all test functions in the keychain package
tests=$(go test -list . ./internal/keychain | grep -E "^Test" | grep -v "^Test.*Integration$")

for test in $tests; do
    echo "----------------------------------------"
    echo "Running: $test"
    echo "----------------------------------------"
    
    SKIP_KEYCHAIN_TESTS=true go test -v ./internal/keychain -run "^${test}$" -count=1
    
    if [ $? -ne 0 ]; then
        echo "FAILED: $test"
    fi
    
    echo ""
    echo "Did you see a keychain prompt? (y/n)"
    read -r response
    
    if [ "$response" = "y" ]; then
        echo "FOUND: $test triggers keychain access!"
        exit 0
    fi
done

echo "No keychain access found in individual tests"