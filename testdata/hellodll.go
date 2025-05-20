// A simple test DLL that writes a file to disk when its export is called
package main

import "C"  // This is critical for CGO exports
import (
    "fmt"
    "os"
)

//export TestDllFunc
func TestDllFunc() bool {
    // Try to write to a file
    err := os.WriteFile("dll_worked.txt", []byte("DLL execution successful"), 0644)
    if err != nil {
        // If file writing fails, at least print to console for logs
        fmt.Println("Failed to write file from DLL but TestDllFunc was called") // Adjusted message
    } else {
        fmt.Println("DLL execution successful, file written by TestDllFunc") // Adjusted message
    }
    return true
}

// This must be defined for proper exports
func main() {}

