//go:build windows
// +build windows

// Package runpe provides functionality to execute PE files in memory.
// This package implements a pure Go reflective PE loader using the Binject/debug/pe package.
// This package only works on Windows systems.
package runpe

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unsafe"

	"syscall"

	"github.com/Binject/debug/pe"
	"golang.org/x/sys/windows"
)

// Constants for PE file characteristics and directory entries
const (
	IMAGE_SCN_MEM_EXECUTE     = 0x20000000
	IMAGE_SCN_MEM_READ        = 0x40000000
	IMAGE_SCN_MEM_WRITE       = 0x80000000
	IMAGE_DIRECTORY_ENTRY_TLS = 9

	// Define DLL_PROCESS_ATTACH for TLS callbacks
	DLL_PROCESS_ATTACH = 1

	// Define the offset of AddressOfCallBacks in the TLS directory
	TLS_CALLBACK_OFFSET_64 = 24
	TLS_CALLBACK_OFFSET_32 = 12

	// Constants for relocations
	IMAGE_REL_BASED_HIGHLOW = 3
	IMAGE_REL_BASED_DIR64   = 10

	// Memory page size
	PAGE_SIZE = 4096
)

// ExecuteInMemory loads and executes a PE file in memory.
func ExecuteInMemory(payload []byte) error {
	// 1. Load the PE file from memory
	reader := bytes.NewReader(payload)
	peFile, err := pe.NewFile(reader)
	if err != nil {
		return fmt.Errorf("PE parse error: %w", err)
	}

	// Validate payload size - check at least SizeOfHeaders is present
	var sizeOfHeaders uint32
	switch oh := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		sizeOfHeaders = oh.SizeOfHeaders
	case *pe.OptionalHeader64:
		sizeOfHeaders = oh.SizeOfHeaders
	default:
		return fmt.Errorf("unsupported PE optional header type")
	}

	if len(payload) < int(sizeOfHeaders) {
		return fmt.Errorf("invalid payload size: %d bytes. Minimum %d bytes expected for PE headers",
			len(payload), sizeOfHeaders)
	}

	// 2. Extract important details from PE headers
	var imageBase uint64
	var sizeOfImage uint32
	var addressOfEntryPoint uint32

	switch oh := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		imageBase = uint64(oh.ImageBase)
		sizeOfImage = oh.SizeOfImage
		addressOfEntryPoint = oh.AddressOfEntryPoint
	case *pe.OptionalHeader64:
		imageBase = oh.ImageBase
		sizeOfImage = oh.SizeOfImage
		addressOfEntryPoint = oh.AddressOfEntryPoint
	default:
		return fmt.Errorf("unsupported PE optional header type")
	}

	// Validate sizeOfImage to prevent OOB errors
	const MAX_REASONABLE_SIZE = 512 * 1024 * 1024 // 512 MB max
	if sizeOfImage == 0 || sizeOfImage > MAX_REASONABLE_SIZE {
		return fmt.Errorf("invalid PE image size: %d bytes", sizeOfImage)
	}

	// 3. Allocate memory for the PE image with multiple strategies (like in the C++ code)
	var baseAddress uintptr
	var allocErr error

	// Strategy 1: Try to allocate at preferred base address
	baseAddress, allocErr = windows.VirtualAlloc(uintptr(imageBase), uintptr(sizeOfImage),
		windows.MEM_RESERVE|windows.MEM_COMMIT,
		windows.PAGE_READWRITE)

	if allocErr != nil {
		// Strategy 2: Let the system choose an address
		baseAddress, allocErr = windows.VirtualAlloc(0, uintptr(sizeOfImage),
			windows.MEM_RESERVE|windows.MEM_COMMIT,
			windows.PAGE_READWRITE)

		if allocErr != nil {
			// Strategy 3: Try reserve + commit in chunks
			var reserveErr error

			// First try at preferred base
			baseAddress, reserveErr = windows.VirtualAlloc(uintptr(imageBase), uintptr(sizeOfImage),
				windows.MEM_RESERVE, windows.PAGE_NOACCESS)

			if reserveErr != nil {
				// If that fails, let system choose
				baseAddress, reserveErr = windows.VirtualAlloc(0, uintptr(sizeOfImage),
					windows.MEM_RESERVE, windows.PAGE_NOACCESS)

				if reserveErr != nil {
					return fmt.Errorf("all memory allocation strategies failed: %w", reserveErr)
				}
			}

			// Commit memory in chunks
			const chunkSize = 64 * 1024 * 1024 // 64MB chunks
			remaining := uintptr(sizeOfImage)
			offset := uintptr(0)
			commitError := false

			for remaining > 0 && !commitError {
				size := remaining
				if size > chunkSize {
					size = chunkSize
				}

				_, err := windows.VirtualAlloc(baseAddress+offset, size,
					windows.MEM_COMMIT, windows.PAGE_READWRITE)

				if err != nil {
					// Don't return immediately, we'll free the reservation below
					commitError = true
					break
				}

				remaining -= size
				offset += size
			}

			if commitError {
				// Free the reservation and try again with system-chosen address
				// but only if we didn't already try that
				windows.VirtualFree(baseAddress, 0, windows.MEM_RELEASE)

				if uintptr(imageBase) == baseAddress {
					// We failed at preferred base, try system-chosen
					baseAddress, allocErr = windows.VirtualAlloc(0, uintptr(sizeOfImage),
						windows.MEM_RESERVE|windows.MEM_COMMIT,
						windows.PAGE_READWRITE)

					if allocErr != nil {
						return fmt.Errorf("all memory allocation strategies failed: %w", allocErr)
					}
				} else {
					// We already tried system-chosen, give up
					return fmt.Errorf("chunked memory commit failed at system-chosen address")
				}
			}
		}
	}

	// Setup cleanup function in case of failure
	cleanup := func() {
		// Free allocated memory
		if baseAddress != 0 {
			windows.VirtualFree(baseAddress, 0, windows.MEM_RELEASE)
		}
	}

	// 4. Create memory destination slice for manipulation
	dest := unsafe.Slice((*byte)(unsafe.Pointer(baseAddress)), sizeOfImage)

	// 5. Copy PE headers
	copy(dest[:sizeOfHeaders], payload[:sizeOfHeaders])

	// 6. Copy sections to their proper virtual addresses
	sectionsWithData := 0
	for _, section := range peFile.Sections {
		// For BSS sections, VirtualSize can be > 0 but Size == 0 (no raw data)
		// We should still process them for proper memory layout, but there's no data to copy
		// The memory was already zero-initialized by VirtualAlloc

		// Skip if section has no virtual space reserved
		if section.VirtualSize == 0 {
			continue
		}

		// If section has raw data, copy it to memory
		if section.Size > 0 {
			// Get section data
			sectionData, err := section.Data()
			if err != nil {
				cleanup()
				return fmt.Errorf("failed to get data for section %s: %w", section.Name, err)
			}

			// Copy section data to its virtual address
			va := section.VirtualAddress
			copy(dest[va:va+uint32(len(sectionData))], sectionData)
			sectionsWithData++
		}
	}

	// 7. Apply relocations if needed
	newImageBase := uint64(baseAddress)
	if newImageBase != imageBase {
		if err := applyRelocations(peFile, dest, imageBase, newImageBase); err != nil {
			cleanup()
			return fmt.Errorf("relocation failed: %w", err)
		}
	}

	// 8. Resolve imports
	if err := resolveImports(peFile, dest); err != nil {
		cleanup()
		return fmt.Errorf("import resolution failed: %w", err)
	}

	// 9. Set proper memory protections for each section
	for _, section := range peFile.Sections {
		if section.VirtualSize == 0 {
			continue
		}

		var protection uint32 = windows.PAGE_READONLY
		characteristics := section.Characteristics

		// Determine protection based on section characteristics (like in C++)
		if characteristics&IMAGE_SCN_MEM_EXECUTE != 0 {
			if characteristics&IMAGE_SCN_MEM_WRITE != 0 {
				// Some PEs rely on PAGE_EXECUTE_WRITECOPY for copy-on-write sections
				// We map all write+exec to EXECUTE_READWRITE for simplicity, but could be refined
				protection = windows.PAGE_EXECUTE_READWRITE
			} else {
				protection = windows.PAGE_EXECUTE_READ
			}
		} else if characteristics&IMAGE_SCN_MEM_WRITE != 0 {
			// Could also differentiate between WRITECOPY and regular WRITE here
			// but we use standard READWRITE for simplicity
			protection = windows.PAGE_READWRITE
		}

		// Apply protection
		var oldProtect uint32
		va := baseAddress + uintptr(section.VirtualAddress)
		size := uintptr(section.VirtualSize)
		// Round up to page boundary
		size = ((size + PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE

		err := windows.VirtualProtect(va, size, protection, &oldProtect)
		if err != nil {
			cleanup()
			return fmt.Errorf("VirtualProtect failed for section %s: %w", section.Name, err)
		}
	}

	// 10. Call TLS callbacks if present
	if err := executeTLSCallbacks(peFile, baseAddress); err != nil {
		cleanup()
		return fmt.Errorf("TLS callback execution failed: %w", err)
	}

	// 11. Execute entry point
	entryPoint := baseAddress + uintptr(addressOfEntryPoint)

	// At this point, we won't call cleanup since the execution takes over the process
	// Note: In a real secure loader, you might want a background goroutine to clean this up
	// after a timeout or if execution doesn't properly take over

	// Call the entry point - this will likely never return as it takes over the process
	syscall.Syscall(entryPoint, 0, 0, 0, 0)

	// In case the call returns (unusual for EXEs but possible for DLLs)
	cleanup()
	return nil
}

// applyRelocations applies base relocations to the PE image
func applyRelocations(peFile *pe.File, imageData []byte, oldBase, newBase uint64) error {
	// Find relocation directory
	var relocDir *pe.DataDirectory

	switch oh := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if len(oh.DataDirectory) > pe.IMAGE_DIRECTORY_ENTRY_BASERELOC {
			relocDir = &oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_BASERELOC]
		}
	case *pe.OptionalHeader64:
		if len(oh.DataDirectory) > pe.IMAGE_DIRECTORY_ENTRY_BASERELOC {
			relocDir = &oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_BASERELOC]
		}
	}

	if relocDir == nil || relocDir.VirtualAddress == 0 || relocDir.Size == 0 {
		return nil // No relocations
	}

	// Track processed size and validate relocation directory
	rva := relocDir.VirtualAddress
	size := relocDir.Size
	endRVA := rva + size

	if endRVA > uint32(len(imageData)) {
		return fmt.Errorf("relocation directory extends beyond image boundaries")
	}

	// Process relocation blocks
	for processedSize := uint32(0); processedSize < size; {
		// Get relocation block
		blockRVA := rva + processedSize

		// Read the block header as two 32-bit values instead of one 64-bit value
		pageRVA := binary.LittleEndian.Uint32(imageData[blockRVA : blockRVA+4])
		blockSize := binary.LittleEndian.Uint32(imageData[blockRVA+4 : blockRVA+8])

		if blockSize == 0 {
			break // End of relocation directory
		}

		if blockSize < 8 || blockRVA+blockSize > endRVA {
			return fmt.Errorf("invalid relocation block: size %d at RVA 0x%X", blockSize, blockRVA)
		}

		entriesCount := (blockSize - 8) / 2 // Each entry is 2 bytes
		for i := uint32(0); i < entriesCount; i++ {
			entryOffset := blockRVA + 8 + i*2
			entry := binary.LittleEndian.Uint16(imageData[entryOffset : entryOffset+2])

			type_val := entry >> 12
			offset := uint32(entry & 0x0FFF)

			relocRVA := pageRVA + offset

			// Apply relocation based on type
			switch type_val {
			case IMAGE_REL_BASED_HIGHLOW: // 32-bit relocation
				if relocRVA+4 > uint32(len(imageData)) {
					return fmt.Errorf("32-bit relocation at RVA 0x%X extends beyond image boundaries", relocRVA)
				}
				addr := binary.LittleEndian.Uint32(imageData[relocRVA : relocRVA+4])
				addr = (addr - uint32(oldBase)) + uint32(newBase)
				binary.LittleEndian.PutUint32(imageData[relocRVA:relocRVA+4], addr)
			case IMAGE_REL_BASED_DIR64: // 64-bit relocation
				if relocRVA+8 > uint32(len(imageData)) {
					return fmt.Errorf("64-bit relocation at RVA 0x%X extends beyond image boundaries", relocRVA)
				}
				addr := binary.LittleEndian.Uint64(imageData[relocRVA : relocRVA+8])
				addr = (addr - oldBase) + newBase
				binary.LittleEndian.PutUint64(imageData[relocRVA:relocRVA+8], addr)
			}
		}

		processedSize += blockSize
	}

	return nil
}

// resolveImports resolves the import table of the PE file
func resolveImports(peFile *pe.File, imageData []byte) error {
	// Find import directory
	var importDir *pe.DataDirectory

	switch oh := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if len(oh.DataDirectory) > pe.IMAGE_DIRECTORY_ENTRY_IMPORT {
			importDir = &oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_IMPORT]
		}
	case *pe.OptionalHeader64:
		if len(oh.DataDirectory) > pe.IMAGE_DIRECTORY_ENTRY_IMPORT {
			importDir = &oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_IMPORT]
		}
	}

	if importDir == nil || importDir.VirtualAddress == 0 || importDir.Size == 0 {
		return nil // No imports
	}

	// Get import descriptors using the RVA
	rva := importDir.VirtualAddress
	if rva >= uint32(len(imageData)) {
		return fmt.Errorf("import directory RVA outside image")
	}

	// Process each import descriptor
	for offset := uint32(0); ; offset += 20 { // Import descriptor is 20 bytes
		// Read import descriptor fields
		descriptorRVA := rva + offset

		// Check if we've reached the end (all zeros descriptor)
		if descriptorRVA+20 > uint32(len(imageData)) {
			break
		}

		// Read the Name RVA field (offset 12 in the descriptor)
		nameRVA := binary.LittleEndian.Uint32(imageData[descriptorRVA+12 : descriptorRVA+16])
		if nameRVA == 0 {
			break // End of import descriptors
		}

		// Read the First Thunk RVA (IAT) field (offset 16 in the descriptor)
		firstThunkRVA := binary.LittleEndian.Uint32(imageData[descriptorRVA+16 : descriptorRVA+20])

		// Read the Original First Thunk RVA (ILT) field (offset 0 in the descriptor)
		originalFirstThunkRVA := binary.LittleEndian.Uint32(imageData[descriptorRVA : descriptorRVA+4])

		// Get DLL name
		if nameRVA >= uint32(len(imageData)) {
			return fmt.Errorf("DLL name RVA outside image")
		}

		dllName := readNullTerminatedString(imageData, nameRVA)
		if dllName == "" {
			return fmt.Errorf("empty DLL name at RVA 0x%X", nameRVA)
		}

		// Load the DLL
		dll, err := windows.LoadLibrary(dllName)
		if err != nil {
			return fmt.Errorf("failed to load library %s: %w", dllName, err)
		}
		defer windows.FreeLibrary(dll)

		// Process imports from this DLL
		thunkRVA := originalFirstThunkRVA
		if thunkRVA == 0 {
			thunkRVA = firstThunkRVA // If no ILT, use IAT
		}

		for thunkOffset := uint32(0); ; thunkOffset += ptrSize(peFile.Machine) {
			thunkEntryRVA := thunkRVA + thunkOffset
			iatEntryRVA := firstThunkRVA + thunkOffset

			if thunkEntryRVA >= uint32(len(imageData)) || iatEntryRVA >= uint32(len(imageData)) {
				break // Out of bounds
			}

			// Read the thunk value
			var ordinal uint64
			var procRVA uint32

			if peFile.Machine == pe.IMAGE_FILE_MACHINE_AMD64 {
				ordinal = binary.LittleEndian.Uint64(imageData[thunkEntryRVA : thunkEntryRVA+8])
				if ordinal == 0 {
					break // End of imports for this DLL
				}
			} else {
				ord32 := binary.LittleEndian.Uint32(imageData[thunkEntryRVA : thunkEntryRVA+4])
				if ord32 == 0 {
					break // End of imports for this DLL
				}
				ordinal = uint64(ord32)
			}

			var procAddr uintptr

			// Check if import by ordinal
			if (peFile.Machine == pe.IMAGE_FILE_MACHINE_AMD64 && (ordinal&0x8000000000000000) != 0) ||
				(peFile.Machine != pe.IMAGE_FILE_MACHINE_AMD64 && (ordinal&0x80000000) != 0) {

				// Import by ordinal
				ord := uint16(ordinal & 0xFFFF)
				procAddr, err = windows.GetProcAddress(dll, "#"+fmt.Sprint(ord))
				if err != nil {
					return fmt.Errorf("failed to get proc address for ordinal %d in %s: %w", ord, dllName, err)
				}
			} else {
				// Import by name
				if peFile.Machine == pe.IMAGE_FILE_MACHINE_AMD64 {
					procRVA = uint32(ordinal & 0xFFFFFFFF)
				} else {
					procRVA = uint32(ordinal)
				}

				// Read the hint/name table entry
				if procRVA+2 >= uint32(len(imageData)) {
					return fmt.Errorf("proc name RVA outside image")
				}

				// Skip the hint (2 bytes)
				procNameRVA := procRVA + 2
				procName := readNullTerminatedString(imageData, procNameRVA)

				procAddr, err = windows.GetProcAddress(dll, procName)
				if err != nil {
					return fmt.Errorf("failed to get proc address for %s in %s: %w", procName, dllName, err)
				}
			}

			// Write the resolved address to the IAT
			if peFile.Machine == pe.IMAGE_FILE_MACHINE_AMD64 {
				binary.LittleEndian.PutUint64(imageData[iatEntryRVA:iatEntryRVA+8], uint64(procAddr))
			} else {
				binary.LittleEndian.PutUint32(imageData[iatEntryRVA:iatEntryRVA+4], uint32(procAddr))
			}
		}
	}

	return nil
}

// executeTLSCallbacks finds and executes TLS callbacks in the PE image
func executeTLSCallbacks(peFile *pe.File, baseAddr uintptr) error {
	// Find TLS directory
	var tlsDir *pe.DataDirectory

	switch oh := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if len(oh.DataDirectory) > IMAGE_DIRECTORY_ENTRY_TLS {
			tlsDir = &oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS]
		}
	case *pe.OptionalHeader64:
		if len(oh.DataDirectory) > IMAGE_DIRECTORY_ENTRY_TLS {
			tlsDir = &oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS]
		}
	}

	if tlsDir == nil || tlsDir.VirtualAddress == 0 || tlsDir.Size == 0 {
		return nil // No TLS directory
	}

	// Get the TLS directory structure based on architecture
	tlsDirVA := baseAddr + uintptr(tlsDir.VirtualAddress)

	var callbacksPtr uintptr
	if peFile.Machine == pe.IMAGE_FILE_MACHINE_AMD64 {
		// 64-bit PE - AddressOfCallBacks is at offset 24
		callbacksPtr = uintptr(binary.LittleEndian.Uint64((*[8]byte)(unsafe.Pointer(tlsDirVA + TLS_CALLBACK_OFFSET_64))[:]))
	} else {
		// 32-bit PE - AddressOfCallBacks is at offset 12
		callbacksPtr = uintptr(binary.LittleEndian.Uint32((*[4]byte)(unsafe.Pointer(tlsDirVA + TLS_CALLBACK_OFFSET_32))[:]))
	}

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

		if peFile.Machine == pe.IMAGE_FILE_MACHINE_AMD64 {
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
		syscall.Syscall(callbackAddr, 3, baseAddr, DLL_PROCESS_ATTACH, 0)
	}

	if callbackCount == MAX_TLS_CALLBACKS {
		return fmt.Errorf("maximum TLS callback limit reached (%d) - possible malformed callback array", MAX_TLS_CALLBACKS)
	}

	return nil
}

// Helper function to read null-terminated strings from memory
func readNullTerminatedString(data []byte, offset uint32) string {
	if offset >= uint32(len(data)) {
		return ""
	}

	// Find null terminator
	end := offset
	for end < uint32(len(data)) && data[end] != 0 {
		end++
	}

	return string(data[offset:end])
}

// Helper function to get pointer size based on machine type
func ptrSize(machine uint16) uint32 {
	if machine == pe.IMAGE_FILE_MACHINE_AMD64 {
		return 8 // 64-bit
	}
	return 4 // 32-bit
}
