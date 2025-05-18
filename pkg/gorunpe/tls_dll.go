//go:build windows
// +build windows

// Package gorunpe provides functionality for executing PE files in memory.
package gorunpe

import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/Binject/debug/pe"
	"gohttpmem/pkg/constants"
)

// ExecuteDLLTLSCallbacks is a specialized version for executing TLS callbacks in DLLs.
// This handles proper TLS callback invocation for DLLs loaded in memory.
func ExecuteDLLTLSCallbacks(peFile *pe.File, base uintptr) error {
	// Locate TLS data directory
	var dir *pe.DataDirectory
	switch h := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		if len(h.DataDirectory) > constants.IMAGE_DIRECTORY_ENTRY_TLS {
			dir = &h.DataDirectory[constants.IMAGE_DIRECTORY_ENTRY_TLS]
		}
	case *pe.OptionalHeader32:
		if len(h.DataDirectory) > constants.IMAGE_DIRECTORY_ENTRY_TLS {
			dir = &h.DataDirectory[constants.IMAGE_DIRECTORY_ENTRY_TLS]
		}
	}
	if dir == nil || dir.VirtualAddress == 0 || dir.Size == 0 {
		// No TLS directory or it's empty
		return nil
	}

	// Calculate pointer to TLS directory in memory
	tlsBase := base + uintptr(dir.VirtualAddress)

	// Read TLS directory information
	var addressOfCallBacks uintptr
	if peFile.Machine == pe.IMAGE_FILE_MACHINE_AMD64 {
		// 64-bit PE
		addressOfCallBacks = uintptr(*(*uint64)(unsafe.Pointer(tlsBase + constants.TLS_CALLBACK_OFFSET_64)))
	} else {
		// 32-bit PE
		addressOfCallBacks = uintptr(*(*uint32)(unsafe.Pointer(tlsBase + constants.TLS_CALLBACK_OFFSET_32)))
	}

	if addressOfCallBacks == 0 {
		// No callbacks registered
		return nil
	}

	// For debugging
	fmt.Printf("DLL TLS Callbacks found at RVA: 0x%x\n", addressOfCallBacks-base)

	// Convert RVA to VA (if necessary)
	if addressOfCallBacks < base {
		addressOfCallBacks += base
	}

	// Iterate through the callback array
	callbackPtr := addressOfCallBacks
	const maxCallbacks = 64 // Reasonable limit to prevent infinite loops
	
	for i := 0; i < maxCallbacks; i++ {
		var callbackAddr uintptr
		
		// Read callback address appropriate for architecture
		if peFile.Machine == pe.IMAGE_FILE_MACHINE_AMD64 {
			callbackAddr = uintptr(*(*uint64)(unsafe.Pointer(callbackPtr)))
			callbackPtr += 8 // Move to next callback pointer (64-bit)
		} else {
			callbackAddr = uintptr(*(*uint32)(unsafe.Pointer(callbackPtr)))
			callbackPtr += 4 // Move to next callback pointer (32-bit)
		}
		
		// End of callbacks is marked by NULL
		if callbackAddr == 0 {
			break
		}
		
		// Ensure callback address is VA not RVA
		if callbackAddr < base {
			callbackAddr += base
		}
		
		fmt.Printf("Calling DLL TLS callback #%d at address: 0x%x\n", i, callbackAddr)
		
		// TLS callbacks in DLLs use the same signature as DllMain:
		// BOOL WINAPI TLSCallback(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
		// Call the TLS callback with DLL_PROCESS_ATTACH
		r1, _, err := syscall.Syscall(callbackAddr, 3, 
			base,                              // DLL base address
			constants.DLL_PROCESS_ATTACH,      // Reason: process attach
			0)                                 // Reserved: NULL for dynamic loads
			
		if r1 == 0 {
			// TLS callbacks may legitimately return FALSE if they fail
			// Log the failure but continue with other callbacks
			fmt.Printf("WARNING: DLL TLS callback #%d returned FALSE (error: %v)\n", i, err)
		}
	}

	return nil
} 