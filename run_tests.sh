#!/bin/bash
set -e  # Exit on error

# Build the test binaries quietly
echo "Building test binaries..."
mkdir -p testdata &>/dev/null
GOOS=windows GOARCH=amd64 go build -o testdata/hello.exe testdata/helloworld.go &>/dev/null

# Set CGO_ENABLED=1 as done in the workflow
export CGO_ENABLED=1
export GOOS=windows

# List contents of testdata directory before tests
echo "Listing contents of testdata directory before tests:"
ls -la testdata

# List tests in pkg directory  
echo "Listing tests in pkg directory:"
cd pkg
go test -list . -tags windows .

# Run tests individually as done in the workflow
echo "Running TestExeExecution..."
go test -v -tags windows . -run "^TestExeExecution$" || {
    echo "TestExeExecution failed"
    exit 1
}

echo "Running TestDllExecution..."
go test -v -tags windows . -run "^TestDllExecution$" || {
    echo "TestDllExecution failed" 
    exit 1
}

echo "All tests completed successfully!"
