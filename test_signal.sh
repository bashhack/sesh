#!/bin/bash

# This script will trigger different signals to test sesh's error handling

echo "This script will trigger signals to test error handling"
echo "1. SIGINT (Ctrl+C equivalent)"
echo "2. SIGTERM (termination signal)"
echo "3. SIGHUP (terminal disconnect equivalent)"
echo "4. SIGQUIT (Ctrl+\ equivalent)"
echo ""
read -p "Enter signal number to test (1-4): " choice

case "$choice" in
    1)
        echo "Sending SIGINT to self..."
        kill -SIGINT $$
        ;;
    2)
        echo "Sending SIGTERM to self..."
        kill -SIGTERM $$
        ;;
    3)
        echo "Sending SIGHUP to self..."
        kill -SIGHUP $$
        ;;
    4)
        echo "Sending SIGQUIT to self..."
        kill -SIGQUIT $$
        ;;
    *)
        echo "Invalid choice"
        exit 1
        ;;
esac

# This should not be reached if signal is handled correctly
echo "This message should not appear"