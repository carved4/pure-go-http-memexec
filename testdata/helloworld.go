// A simple test binary that writes a file to disk when executed
package main

import (
    "fmt"
    "os"
)

func main() {
    // Try to write to a file
    err := os.WriteFile("it_worked.txt", []byte("EXE execution successful"), 0644)
    if err != nil {
        // If file writing fails, at least print to console for logs
        fmt.Println("Failed to write file but EXE execution successful")
    } else {
        fmt.Println("EXE execution successful, file written")
    }
} 