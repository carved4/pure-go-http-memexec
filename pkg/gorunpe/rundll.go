// Package runpe provides functionality to execute PE files in memory.
// This package implements a pure Go reflective DLL loader using the Binject/debug/pe package.
// This package only works on Windows systems.
// +build windows
package gorunpe

import (
	"bytes"
	"fmt"
	"unsafe"
	
	"gohttpmem/pkg/constants"
	"github.com/Binject/debug/pe"
	"golang.org/x/sys/windows"
	"syscall"
)

// Windows structures needed for export parsing
// These are not defined in golang.org/x/sys/windows package

// ImageDosHeader represents the DOS header of a PE file
type ImageDosHeader struct {
	E_magic    uint16     // Magic number
	E_cblp     uint16     // Bytes on last page of file
	E_cp       uint16     // Pages in file
	E_crlc     uint16     // Relocations
	E_cparhdr  uint16     // Size of header in paragraphs
	E_minalloc uint16     // Minimum extra paragraphs needed
	E_maxalloc uint16     // Maximum extra paragraphs needed
	E_ss       uint16     // Initial (relative) SS value
	E_sp       uint16     // Initial SP value
	E_csum     uint16     // Checksum
	E_ip       uint16     // Initial IP value
	E_cs       uint16     // Initial (relative) CS value
	E_lfarlc   uint16     // File address of relocation table
	E_ovno     uint16     // Overlay number
	E_res      [4]uint16  // Reserved words
	E_oemid    uint16     // OEM identifier (for e_oeminfo)
	E_oeminfo  uint16     // OEM information; e_oemid specific
	E_res2     [10]uint16 // Reserved words
	E_lfanew   int32      // File address of new exe header
}

// ImageDataDirectory represents a data directory in PE optional header
type ImageDataDirectory struct {
	VirtualAddress uint32
	Size           uint32
}

// ImageOptionalHeader32 represents the PE32 optional header
type ImageOptionalHeader32 struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	BaseOfData                  uint32
	ImageBase                   uint32
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint32
	SizeOfStackCommit           uint32
	SizeOfHeapReserve           uint32
	SizeOfHeapCommit            uint32
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [16]ImageDataDirectory
}

// ImageOptionalHeader64 represents the PE32+ optional header
type ImageOptionalHeader64 struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [16]ImageDataDirectory
}

// ImageFileHeader represents the PE file header
type ImageFileHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

// ImageNtHeaders32 represents the PE NT headers for 32-bit files
type ImageNtHeaders32 struct {
	Signature      uint32
	FileHeader     ImageFileHeader
	OptionalHeader ImageOptionalHeader32
}

// ImageNtHeaders64 represents the PE NT headers for 64-bit files
type ImageNtHeaders64 struct {
	Signature      uint32
	FileHeader     ImageFileHeader
	OptionalHeader ImageOptionalHeader64
}

// ImageExportDirectory represents the export directory
type ImageExportDirectory struct {
	Characteristics       uint32
	TimeDateStamp         uint32
	MajorVersion          uint16
	MinorVersion          uint16
	Name                  uint32
	Base                  uint32
	NumberOfFunctions     uint32
	NumberOfNames         uint32
	AddressOfFunctions    uint32
	AddressOfNames        uint32
	AddressOfNameOrdinals uint32
}

// LoadDLLInMemory loads a PE that's built as a DLL entirely into the current process.
// It does everything ExecuteInMemory does up through VirtualProtect,
// then calls DllMain with DLL_PROCESS_ATTACH.
// Returns the base address of the loaded DLL as a handle, and any error encountered.
func LoadDLLInMemory(dllBytes []byte) (handle uintptr, err error) {
	// 1. Parse the PE file from memory
	reader := bytes.NewReader(dllBytes)
	peFile, err := pe.NewFile(reader)
	if err != nil {
		return 0, fmt.Errorf("PE parse error: %w", err)
	}

	// Validate payload size - check at least SizeOfHeaders is present
	var sizeOfHeaders uint32
	switch oh := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		sizeOfHeaders = oh.SizeOfHeaders
	case *pe.OptionalHeader64:
		sizeOfHeaders = oh.SizeOfHeaders
	default:
		return 0, fmt.Errorf("unsupported PE optional header type")
	}

	if len(dllBytes) < int(sizeOfHeaders) {
		return 0, fmt.Errorf("invalid payload size: %d bytes. Minimum %d bytes expected for PE headers",
			len(dllBytes), sizeOfHeaders)
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
		return 0, fmt.Errorf("unsupported PE optional header type")
	}

	// Validate sizeOfImage to prevent OOB errors
	const MAX_REASONABLE_SIZE = 512 * 1024 * 1024 // 512 MB max
	if sizeOfImage == 0 || sizeOfImage > MAX_REASONABLE_SIZE {
		return 0, fmt.Errorf("invalid PE image size: %d bytes", sizeOfImage)
	}

	// 3. Allocate memory for the DLL with proper permissions
	baseAddress, allocErr := windows.VirtualAlloc(0, uintptr(sizeOfImage),
		windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_READWRITE)
	if allocErr != nil {
		return 0, fmt.Errorf("memory allocation failed: %w", allocErr)
	}

	// Setup cleanup function in case of failure
	var success bool
	defer func() {
		if !success && baseAddress != 0 {
			windows.VirtualFree(baseAddress, 0, windows.MEM_RELEASE)
		}
	}()

	// 4. Create memory destination slice for manipulation
	dest := unsafe.Slice((*byte)(unsafe.Pointer(baseAddress)), sizeOfImage)

	// 5. Copy PE headers to memory
	copy(dest[:sizeOfHeaders], dllBytes[:sizeOfHeaders])

	// 6. Copy sections to their proper virtual addresses
	for _, section := range peFile.Sections {
		// Skip if section has no virtual space reserved
		if section.VirtualSize == 0 {
			continue
		}
		
		// If section has raw data, copy it to memory
		if section.Size > 0 {
			// Get section data
			sectionData, err := section.Data()
			if err != nil {
				return 0, fmt.Errorf("failed to get data for section %s: %w", section.Name, err)
			}

			// Copy section data to its virtual address
			va := section.VirtualAddress
			copy(dest[va:va+uint32(len(sectionData))], sectionData)
		}
	}

	// 7. Apply relocations if needed
	newImageBase := uint64(baseAddress)
	if newImageBase != imageBase {
		if err := ApplyRelocations(peFile, dest, imageBase, newImageBase); err != nil {
			// Free allocated memory
			windows.VirtualFree(baseAddress, 0, windows.MEM_RELEASE)
			return 0, fmt.Errorf("relocation failed: %w", err)
		}
	}

	// 8. Resolve imports
	if err := ResolveImports(peFile, dest); err != nil {
		// Free allocated memory
		windows.VirtualFree(baseAddress, 0, windows.MEM_RELEASE)
		return 0, fmt.Errorf("import resolution failed: %w", err)
	}

	// 9. Set proper memory protections for each section
	for _, section := range peFile.Sections {
		if section.VirtualSize == 0 {
			continue
		}

		var protection uint32 = windows.PAGE_READONLY
		characteristics := section.Characteristics

		// Determine protection based on section characteristics
		if characteristics&constants.IMAGE_SCN_MEM_EXECUTE != 0 {
			if characteristics&constants.IMAGE_SCN_MEM_WRITE != 0 {
				// Some DLLs rely on PAGE_EXECUTE_WRITECOPY for copy-on-write sections
				// We map all write+exec to EXECUTE_READWRITE for simplicity
				protection = windows.PAGE_EXECUTE_READWRITE
			} else {
				protection = windows.PAGE_EXECUTE_READ
			}
		} else if characteristics&constants.IMAGE_SCN_MEM_WRITE != 0 {
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
			return 0, fmt.Errorf("VirtualProtect failed for section %s: %w", section.Name, err)
		}
	}

	// 10. Call TLS callbacks if present
	if err := ExecuteTLSCallbacks(peFile, baseAddress); err != nil {
		// Free allocated memory
		windows.VirtualFree(baseAddress, 0, windows.MEM_RELEASE)
		return 0, fmt.Errorf("TLS callback execution failed: %w", err)
	}

	// 11. Call DllMain with DLL_PROCESS_ATTACH
	// For DLLs, the entry point is DllMain
	if addressOfEntryPoint != 0 {
		dllMain := baseAddress + uintptr(addressOfEntryPoint)
		
		// Call DllMain(hinstDLL, DLL_PROCESS_ATTACH, lpvReserved)
		// DLL_PROCESS_ATTACH = 1
		// Use 0 for lpvReserved (static load) rather than a real pointer (dynamic load)
		r1, _, errCode := syscall.Syscall(dllMain, 3, baseAddress, constants.DLL_PROCESS_ATTACH, 0)
		
		// DllMain returns TRUE (non-zero) on success
		if errCode != 0 {
			return 0, fmt.Errorf("DllMain call failed with error code: %v", errCode)
		}
		
		if r1 == 0 {
			return 0, fmt.Errorf("DllMain returned FALSE (0)")
		}
	}

	// Mark success so deferred cleanup doesn't free the memory
	success = true
	
	// Return the base address as the handle to the loaded DLL
	return baseAddress, nil
}

// GetProcAddressFromMemoryDLL gets the address of an exported function from a DLL loaded in memory.
func GetProcAddressFromMemoryDLL(dllBase uintptr, procName string) (uintptr, error) {
	// We need to find the export directory and manually look up the function
	// since Windows GetProcAddress only works with officially loaded modules.
	// First, we need to parse the PE headers at the base address

	// Get DOS header
	dosHeader := (*ImageDosHeader)(unsafe.Pointer(dllBase))
	if dosHeader.E_magic != 0x5A4D { // "MZ"
		return 0, fmt.Errorf("invalid DOS header signature")
	}

	// Get NT headers
	ntHeadersOffset := dllBase + uintptr(dosHeader.E_lfanew)
	ntHeaders32 := (*ImageNtHeaders32)(unsafe.Pointer(ntHeadersOffset))
	
	// Determine if 32-bit or 64-bit PE
	var exportDirRVA uint32
	var exportDirSize uint32
	
	if ntHeaders32.Signature != 0x4550 { // "PE\0\0"
		return 0, fmt.Errorf("invalid NT headers signature")
	}
	
	// Find export directory
	if ntHeaders32.OptionalHeader.Magic == 0x10b { // 32-bit PE
		// Extract from 32-bit optional header
		exportDirRVA = ntHeaders32.OptionalHeader.DataDirectory[0].VirtualAddress
		exportDirSize = ntHeaders32.OptionalHeader.DataDirectory[0].Size
	} else if ntHeaders32.OptionalHeader.Magic == 0x20b { // 64-bit PE
		// We need to cast to 64-bit NT headers structure
		ntHeaders64 := (*ImageNtHeaders64)(unsafe.Pointer(ntHeadersOffset))
		exportDirRVA = ntHeaders64.OptionalHeader.DataDirectory[0].VirtualAddress
		exportDirSize = ntHeaders64.OptionalHeader.DataDirectory[0].Size
	} else {
		return 0, fmt.Errorf("unknown PE format")
	}
	
	if exportDirRVA == 0 || exportDirSize == 0 {
		return 0, fmt.Errorf("no export directory found")
	}
	
	// Get export directory
	exportDir := (*ImageExportDirectory)(unsafe.Pointer(dllBase + uintptr(exportDirRVA)))
	
	// Get export tables
	namesRVA := dllBase + uintptr(exportDir.AddressOfNames)
	ordinalsRVA := dllBase + uintptr(exportDir.AddressOfNameOrdinals)
	functionsRVA := dllBase + uintptr(exportDir.AddressOfFunctions)
	
	// Search for the requested function name
	for i := uint32(0); i < exportDir.NumberOfNames; i++ {
		// Get the RVA of the function name
		nameRVA := *(*uint32)(unsafe.Pointer(namesRVA + uintptr(i*4)))
		
		// Get the function name
		funcName := windows.BytePtrToString((*byte)(unsafe.Pointer(dllBase + uintptr(nameRVA))))
		
		if funcName == procName {
			// Get the ordinal
			ordinal := *(*uint16)(unsafe.Pointer(ordinalsRVA + uintptr(i*2)))
			
			// Get the function RVA
			funcRVA := *(*uint32)(unsafe.Pointer(functionsRVA + uintptr(uint32(ordinal)*4)))
			
			// Calculate the function address
			funcAddr := dllBase + uintptr(funcRVA)
			
			// Check if the function is forwarded
			if funcRVA >= exportDirRVA && funcRVA < (exportDirRVA+exportDirSize) {
				// Function is forwarded - we need to resolve the forwarded function
				// This is a more advanced case and would require loading another DLL
				return 0, fmt.Errorf("forwarded exports are not supported")
			}
			
			return funcAddr, nil
		}
	}
	
	return 0, fmt.Errorf("procedure %s not found in exports", procName)
}

// GetProcAddressByOrdinalFromMemoryDLL gets the address of an exported function from a DLL loaded in memory using its ordinal.
func GetProcAddressByOrdinalFromMemoryDLL(dllBase uintptr, ordinal uint16) (uintptr, error) {
	// We need to find the export directory and look up the function by ordinal
	// First, we need to parse the PE headers at the base address

	// Get DOS header
	dosHeader := (*ImageDosHeader)(unsafe.Pointer(dllBase))
	if dosHeader.E_magic != 0x5A4D { // "MZ"
		return 0, fmt.Errorf("invalid DOS header signature")
	}

	// Get NT headers
	ntHeadersOffset := dllBase + uintptr(dosHeader.E_lfanew)
	ntHeaders32 := (*ImageNtHeaders32)(unsafe.Pointer(ntHeadersOffset))
	
	// Determine if 32-bit or 64-bit PE
	var exportDirRVA uint32
	var exportDirSize uint32
	
	if ntHeaders32.Signature != 0x4550 { // "PE\0\0"
		return 0, fmt.Errorf("invalid NT headers signature")
	}
	
	// Find export directory
	if ntHeaders32.OptionalHeader.Magic == 0x10b { // 32-bit PE
		// Extract from 32-bit optional header
		exportDirRVA = ntHeaders32.OptionalHeader.DataDirectory[0].VirtualAddress
		exportDirSize = ntHeaders32.OptionalHeader.DataDirectory[0].Size
	} else if ntHeaders32.OptionalHeader.Magic == 0x20b { // 64-bit PE
		// We need to cast to 64-bit NT headers structure
		ntHeaders64 := (*ImageNtHeaders64)(unsafe.Pointer(ntHeadersOffset))
		exportDirRVA = ntHeaders64.OptionalHeader.DataDirectory[0].VirtualAddress
		exportDirSize = ntHeaders64.OptionalHeader.DataDirectory[0].Size
	} else {
		return 0, fmt.Errorf("unknown PE format")
	}
	
	if exportDirRVA == 0 || exportDirSize == 0 {
		return 0, fmt.Errorf("no export directory found")
	}
	
	// Get export directory
	exportDir := (*ImageExportDirectory)(unsafe.Pointer(dllBase + uintptr(exportDirRVA)))
	
	// Validate ordinal
	baseOrdinal := exportDir.Base
	if uint32(ordinal) < baseOrdinal || uint32(ordinal) >= baseOrdinal+exportDir.NumberOfFunctions {
		return 0, fmt.Errorf("ordinal %d out of range (valid range: %d-%d)", 
			ordinal, baseOrdinal, baseOrdinal+exportDir.NumberOfFunctions-1)
	}
	
	// Calculate the index into the function address table
	funcIndex := uint32(ordinal) - baseOrdinal
	
	// Get function address from the function table
	functionsRVA := dllBase + uintptr(exportDir.AddressOfFunctions)
	funcRVA := *(*uint32)(unsafe.Pointer(functionsRVA + uintptr(funcIndex*4)))
	
	// Calculate the function address
	funcAddr := dllBase + uintptr(funcRVA)
	
	// Check if the function is forwarded
	if funcRVA >= exportDirRVA && funcRVA < (exportDirRVA+exportDirSize) {
		// Function is forwarded - we need to resolve the forwarded function
		// This is a more advanced case and would require loading another DLL
		return 0, fmt.Errorf("forwarded exports are not supported")
	}
	
	return funcAddr, nil
}

// FreeDLLFromMemory frees a DLL previously loaded with LoadDLLInMemory.
// It calls DllMain with DLL_PROCESS_DETACH and then frees the memory.
func FreeDLLFromMemory(dllBase uintptr, entryPoint uintptr) error {
	if dllBase == 0 {
		return fmt.Errorf("invalid DLL handle (NULL)")
	}
	
	// If we know the entry point, call DllMain with DLL_PROCESS_DETACH
	if entryPoint != 0 {
		syscall.Syscall(entryPoint, 3, dllBase, constants.DLL_PROCESS_DETACH, 0)
		// Ignore result - we're going to free the memory anyway
	}
	
	// Free the allocated memory
	err := windows.VirtualFree(dllBase, 0, windows.MEM_RELEASE)
	if err != nil {
		return fmt.Errorf("failed to free DLL memory: %w", err)
	}
	
	return nil
} 