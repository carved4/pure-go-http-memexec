//go:build windows
// +build windows

// Package runpe provides functionality to execute PE files in memory.
// This package implements a pure Go reflective PE loader using the Binject/debug/pe package.
// This package only works on Windows systems.
package gorunpe

import (

	"encoding/binary"
	"fmt"
	"unsafe"

	"syscall"
	"gohttpmem/pkg/constants"
	"github.com/Binject/debug/pe"
)

// ExecuteTLSCallbacks finds and executes TLS callbacks in the PE image
func ExecuteTLSCallbacks(peFile *pe.File, baseAddr uintptr) error {
	// Find TLS directory
	var tlsDir *pe.DataDirectory

	switch oh := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if len(oh.DataDirectory) > constants.IMAGE_DIRECTORY_ENTRY_TLS {
			tlsDir = &oh.DataDirectory[constants.IMAGE_DIRECTORY_ENTRY_TLS]
		}
	case *pe.OptionalHeader64:
		if len(oh.DataDirectory) > constants.IMAGE_DIRECTORY_ENTRY_TLS {
			tlsDir = &oh.DataDirectory[constants.IMAGE_DIRECTORY_ENTRY_TLS]
		}
	}

	if tlsDir == nil || tlsDir.VirtualAddress == 0 || tlsDir.Size == 0 {
		return nil // No TLS directory
	}

	// Get the TLS directory structure based on architecture
	tlsDirVA := baseAddr + uintptr(tlsDir.VirtualAddress)

	var callbacksPtr uintptr
	var addressOfCallBacksRaw uint64 // Use uint64 to hold raw value, might be RVA

	if peFile.Machine == constants.IMAGE_FILE_MACHINE_AMD64 {
		// 64-bit PE - AddressOfCallBacks is at offset 24
		addressOfCallBacksRaw = binary.LittleEndian.Uint64((*[8]byte)(unsafe.Pointer(tlsDirVA + constants.TLS_CALLBACK_OFFSET_64))[:])
	} else {
		// 32-bit PE - AddressOfCallBacks is at offset 12
		// Read as uint32 then promote to uint64 for consistent handling
		addressOfCallBacksRaw = uint64(binary.LittleEndian.Uint32((*[4]byte)(unsafe.Pointer(tlsDirVA + constants.TLS_CALLBACK_OFFSET_32))[:]))
	}

	// If AddressOfCallBacksRaw is 0, there are no callbacks.
	if addressOfCallBacksRaw == 0 {
		return nil
	}

	// Assume addressOfCallBacksRaw is an RVA and convert to absolute VA.
	// This is a common case for this field.
	callbacksPtr = baseAddr + uintptr(addressOfCallBacksRaw)

	// If no callbacks, return
	if callbacksPtr == 0 {
		return nil
	}

	// Iterate through the callbacks (they are stored as a NULL-terminated array of function pointers)
	cbPtr := callbacksPtr
	callbackCount := 0
	const MAX_TLS_CALLBACKS = 128 // Safety limit to prevent infinite loops

	for callbackCount < MAX_TLS_CALLBACKS {
		var callbackAddr uintptr

		if peFile.Machine == constants.IMAGE_FILE_MACHINE_AMD64 {
			// 64-bit PE
			cbValue := binary.LittleEndian.Uint64((*[8]byte)(unsafe.Pointer(cbPtr))[:])
			if cbValue == 0 {
				break // End of callbacks
			}
			callbackAddr = uintptr(cbValue)
			cbPtr += 8 // Move to next callback
		} else {
			// 32-bit PE
			cbValue := binary.LittleEndian.Uint32((*[4]byte)(unsafe.Pointer(cbPtr))[:])
			if cbValue == 0 {
				break // End of callbacks
			}
			callbackAddr = uintptr(cbValue)
			cbPtr += 4 // Move to next callback
		}

		// Execute the callback
		callbackCount++
		syscall.Syscall(callbackAddr, 3, baseAddr, constants.DLL_PROCESS_ATTACH, 0)
	}

	if callbackCount == MAX_TLS_CALLBACKS {
		return fmt.Errorf("maximum TLS callback limit reached (%d) - possible malformed callback array", MAX_TLS_CALLBACKS)
	}

	return nil
}
