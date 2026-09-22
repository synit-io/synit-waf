#!/bin/bash
set -e

# Ensure we are in the project root
cd "$(dirname "$0")/.."

echo "Running End-to-End Integration Tests..."



if ! command -v go &> /dev/null; then
    echo "Error: 'go' command not found. Go is required for e2e tests."
    exit 1
fi

# Run the tests
go test -v -count=1 ./test/e2e/...

echo "E2E Tests completed successfully."
