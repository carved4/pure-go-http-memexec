# Integration Testing for pure-go-http-memexec

This document describes the integration testing approach for this project.

## Test Files

The integration tests use two simple test binaries:

1. `testdata/hello.exe` - A simple Windows executable that writes a file to disk
2. `testdata/hello.dll` - A simple Windows DLL with an exported function that writes a file to disk

## Building Test Binaries

Before running the tests, you need to build the test binaries:

```bash
# Using the Makefile
make build-test-binaries

# Or manually
GOOS=windows GOARCH=amd64 go build -o testdata/hello.exe testdata/helloworld.go
GOOS=windows GOARCH=amd64 CGO_ENABLED=1 go build -buildmode=c-shared -o testdata/hello.dll testdata/hellodll.go
```

## Running Tests

To run the integration tests:

```bash
# Using the Makefile (builds the test binaries first)
make test

# Or manually (assuming binaries are already built)
go test ./...
```

## Test Details

The integration tests verify:

1. **EXE Execution Test** - Tests the `gorunpe.ExecuteInMemory` function to ensure it can load and execute a Windows executable in memory
2. **DLL Execution Test** - Tests the DLL handling functions (`LoadDLLInMemory`, `CallExportWithNoArgs`, etc.) to ensure they can load a DLL in memory and execute exported functions

## CI Integration

This project includes a GitHub Actions workflow that automatically builds the test binaries and runs the integration tests on Windows environments.

The workflow is defined in `.github/workflows/go.yml` and runs on every push to main/master branches and pull requests. 