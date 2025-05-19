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

# Check the DLL exports if objdump is available (optional)
if command -v objdump &> /dev/null; then
    if [ -f "testdata/hello.dll" ]; then
        echo "DLL exports (for pre-built hello.dll):"
        objdump -p testdata/hello.dll | grep -A20 "Export Table"
    else
        echo "Warning: testdata/hello.dll not found. Skipping DLL export check."
    fi
fi

# Create coverage directory
mkdir -p coverage

# Run tests separately with coverage
echo "Running TestExeExecution with coverage..."
(cd pkg && CGO_ENABLED=1 GOOS=windows GOARCH=amd64 go test -v . -run "^TestExeExecution$" -coverprofile=../coverage/exe.out) || exit 1

echo "Running TestDllExecution with coverage..."
(cd pkg && CGO_ENABLED=1 GOOS=windows GOARCH=amd64 go test -v . -run "^TestDllExecution$" -coverprofile=../coverage/dll.out) || exit 1

# Check if coverage files exist before trying to combine them
if [ -f "coverage/exe.out" ] && [ -f "coverage/dll.out" ]; then
    echo "Combining coverage reports..."
    echo "mode: set" > coverage/coverage.out
    tail -n +2 -q coverage/exe.out coverage/dll.out >> coverage/coverage.out 2>/dev/null || true

    # Generate HTML coverage report
    echo "Generating HTML coverage report..."
    go tool cover -html=coverage/coverage.out -o coverage/coverage.html
    echo "Coverage report generated at coverage/coverage.html"
else
    echo "Warning: Coverage files not found. Skipping coverage report generation."
fi

echo "All tests completed successfully!"