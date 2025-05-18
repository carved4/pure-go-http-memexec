#!/bin/bash
set -e  # Exit on error

echo "Building test binaries..."

# Create testdata directory if it doesn't exist
mkdir -p testdata

echo "Building EXE..."
GOOS=windows GOARCH=amd64 go build -o testdata/hello.exe testdata/helloworld.go

# Fix the hellodll.go file to ensure syscall is imported
grep -q "syscall" testdata/hellodll.go || sed -i 's/import (/import (\n    "syscall"/' testdata/hellodll.go

echo "Building DLL..."
GOOS=windows GOARCH=amd64 CGO_ENABLED=1 go build -ldflags="-s -w" -buildmode=c-shared -o testdata/hello.dll testdata/hellodll.go

# Check the DLL exports if objdump is available
if command -v objdump &> /dev/null; then
    echo "DLL exports:"
    objdump -p testdata/hello.dll | grep -A20 "Export Table"
fi

# Run both tests together
echo "Running all tests..."
go test -v gohttpmem/pkg -run "TestExeExecution|TestDllExecution"

echo "All tests completed!"