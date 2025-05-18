#!/bin/bash
set -e  # Exit on error

echo "Building test EXE (DLL should be pre-built and committed)..."

# Create testdata directory if it doesn't exist
mkdir -p testdata

echo "Building EXE..."
GOOS=windows GOARCH=amd64 go build -o testdata/hello.exe testdata/helloworld.go

# The following lines for fixing and rebuilding hello.dll are removed:
# grep -q "syscall" testdata/hellodll.go || sed -i 's/import (/import (\n    "syscall"/' testdata/hellodll.go
# echo "Building DLL..."
# GOOS=windows GOARCH=amd64 CGO_ENABLED=1 go build -ldflags="-s -w" -buildmode=c-shared -o testdata/hello.dll testdata/hellodll.go

# Check the DLL exports if objdump is available (optional, can be kept or removed)
# This will now check the pre-built DLL
if command -v objdump &> /dev/null; then
    if [ -f "testdata/hello.dll" ]; then
        echo "DLL exports (for pre-built hello.dll):"
        objdump -p testdata/hello.dll | grep -A20 "Export Table"
    else
        echo "Warning: testdata/hello.dll not found. Skipping DLL export check."
    fi
fi

# Run tests separately
echo "Running TestExeExecution..."
(cd pkg && CGO_ENABLED=1 GOOS=windows GOARCH=amd64 go test -v . -run "^TestExeExecution$")

echo "Running TestDllExecution..."
(cd pkg && CGO_ENABLED=1 GOOS=windows GOARCH=amd64 go test -v . -run "^TestDllExecution$")

echo "All tests completed!"