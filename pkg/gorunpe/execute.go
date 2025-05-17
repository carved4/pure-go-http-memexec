package gorunpe

import (
	"bytes"
	"fmt"
	"unsafe"
	"syscall"
	"github.com/Binject/debug/pe"
	"golang.org/x/sys/windows"
)

var (
	modNtdll               = syscall.NewLazyDLL("ntdll.dll")
	procNtCreateSection    = modNtdll.NewProc("NtCreateSection")
	procNtMapViewOfSection = modNtdll.NewProc("NtMapViewOfSection")

	modKernel32      = syscall.NewLazyDLL("kernel32.dll")
	procCreateThread = modKernel32.NewProc("CreateThread")
)

// NTSTATUS type for checking return values from NT functions
type NTSTATUS uintptr

// ACCESS_MASK for NTAPI permissions
type ACCESS_MASK uint32

// SECTION_INHERIT for NtMapViewOfSection
type SECTION_INHERIT uint32

const (
	STATUS_SUCCESS                NTSTATUS      = 0x00000000
	SECTION_MAP_READ              ACCESS_MASK   = 0x0004
	SECTION_MAP_WRITE             ACCESS_MASK   = 0x0002
	SECTION_MAP_EXECUTE           ACCESS_MASK   = 0x0008
	NT_SECTION_DESIRED_ACCESS     ACCESS_MASK   = SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE // 0xE
	ViewShare                     SECTION_INHERIT = 1
	SEC_COMMIT_LITERAL            uint32        = 0x08000000 // Using literal due to potential environment issues with windows.SEC_COMMIT
)

// ntCreateSection wraps the NtCreateSection syscall.
func ntCreateSection(sizeOfImage uint32) (sectionHandle windows.Handle, err error) {
	var hSection windows.Handle
	maxSize := int64(sizeOfImage) // NtCreateSection expects *LARGE_INTEGER

	// NtCreateSection(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle)
	r1, _, e1 := procNtCreateSection.Call(
		uintptr(unsafe.Pointer(&hSection)), // SectionHandle (*PHANDLE)
		uintptr(NT_SECTION_DESIRED_ACCESS), // DesiredAccess (ACCESS_MASK)
		0,                                  // ObjectAttributes (*POBJECT_ATTRIBUTES = NULL)
		uintptr(unsafe.Pointer(&maxSize)),  // MaximumSize (*PLARGE_INTEGER)
		windows.PAGE_EXECUTE_READWRITE,     // SectionPageProtection (ULONG)
		uintptr(SEC_COMMIT_LITERAL),        // AllocationAttributes (ULONG)
		0)                                  // FileHandle (HANDLE = NULL for pagefile-backed)

	if e1 != nil && e1 != syscall.Errno(0) { // Check for actual error from Call itself
		return 0, fmt.Errorf("NtCreateSection system call failed: %w", e1)
	}
	if NTSTATUS(r1) != STATUS_SUCCESS {
		return 0, fmt.Errorf("NtCreateSection failed with NTSTATUS: 0x%x", NTSTATUS(r1))
	}
	return hSection, nil
}

// ntMapViewOfSection wraps the NtMapViewOfSection syscall.
func ntMapViewOfSection(sectionHandle windows.Handle, sizeOfImage uint32) (baseAddress uintptr, err error) {
	var bAddress uintptr
	viewSize := uintptr(sizeOfImage) // NtMapViewOfSection expects *PSIZE_T for ViewSize

	// NtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect)
	r1, _, e1 := procNtMapViewOfSection.Call(
		uintptr(sectionHandle),              // SectionHandle
		uintptr(windows.CurrentProcess()),   // ProcessHandle (GetCurrentProcess())
		uintptr(unsafe.Pointer(&bAddress)),  // BaseAddress (*PVOID, set to 0 for system to choose)
		0,                                   // ZeroBits (ULONG_PTR)
		0,                                   // CommitSize (SIZE_T, 0 to map entire committed section)
		0,                                   // SectionOffset (*PLARGE_INTEGER, NULL)
		uintptr(unsafe.Pointer(&viewSize)),  // ViewSize (*PSIZE_T, map entire section)
		uintptr(ViewShare),                  // InheritDisposition (SECTION_INHERIT)
		0,                                   // AllocationType (ULONG, 0 for MEM_COMMIT if section is SEC_COMMIT)
		windows.PAGE_EXECUTE_READWRITE)      // Win32Protect (ULONG)

	if e1 != nil && e1 != syscall.Errno(0) { // Check for actual error from Call itself
		return 0, fmt.Errorf("NtMapViewOfSection system call failed: %w", e1)
	}
	if NTSTATUS(r1) != STATUS_SUCCESS {
		return 0, fmt.Errorf("NtMapViewOfSection failed with NTSTATUS: 0x%x", NTSTATUS(r1))
	}
	if bAddress == 0 {
		return 0, fmt.Errorf("NtMapViewOfSection returned a NULL base address")
	}
	return bAddress, nil
}

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

	// 3. Allocate memory for the PE image using NtCreateSection and NtMapViewOfSection
	var baseAddress uintptr
	var sectionHandle windows.Handle

	sectionHandle, err = ntCreateSection(sizeOfImage)
	if err != nil {
		return fmt.Errorf("ntCreateSection failed: %w", err)
	}
	// Ensure the section handle is closed when the function returns or panics
	defer func() {
		if sectionHandle != 0 {
			windows.CloseHandle(sectionHandle)
		}
	}()

	baseAddress, err = ntMapViewOfSection(sectionHandle, sizeOfImage)
	if err != nil {
		// sectionHandle will be closed by the defer above
		return fmt.Errorf("ntMapViewOfSection failed: %w", err)
	}
	
	// Setup cleanup function for unmapping the view in case of failure before execution takes over
	// The section handle is closed by its own defer statement.
	cleanup := func() {
		if baseAddress != 0 {
			windows.UnmapViewOfFile(baseAddress) // NtUnmapViewOfSection could also be used here
			// baseAddress = 0 // Mark as unmapped
		}
	}

	// 4. Create memory destination slice for manipulation
	dest := unsafe.Slice((*byte)(unsafe.Pointer(baseAddress)), sizeOfImage)

	// 5. Copy PE headers
	copy(dest[:sizeOfHeaders], payload[:sizeOfHeaders])

	// 6. Copy sections to their proper virtual addresses
	// sectionsWithData := 0 // This variable is not used
	for _, section := range peFile.Sections {
		// For BSS sections, VirtualSize can be > 0 but Size == 0 (no raw data)
		// We should still process them for proper memory layout, but there's no data to copy
		// The memory was already zero-initialized by NtCreateSection(SEC_COMMIT) + NtMapViewOfSection.
		
		if section.VirtualSize == 0 {
			continue
		}
		
		if section.Size > 0 {
			sectionData, err := section.Data()
			if err != nil {
				cleanup()
				return fmt.Errorf("failed to get data for section %s: %w", section.Name, err)
			}
			va := section.VirtualAddress
			copy(dest[va:va+uint32(len(sectionData))], sectionData)
			// sectionsWithData++
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

	// 9. Memory protections are already PAGE_EXECUTE_READWRITE for the entire section.
	// The previous VirtualProtect loop is not needed.

	// 10. Call TLS callbacks if present
	if err := ExecuteTLSCallbacks(peFile, baseAddress); err != nil {
		cleanup()
		return fmt.Errorf("TLS callback execution failed: %w", err)
	}

	// 11. Execute entry point using CreateThread
	entryPoint := baseAddress + uintptr(addressOfEntryPoint)
	var threadId uint32

	// CreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId)
	hThread, _, e1 := procCreateThread.Call(
		0,                               // lpThreadAttributes (NULL)
		0,                               // dwStackSize (0 for default)
		entryPoint,                      // lpStartAddress
		0,                               // lpParameter (NULL)
		0,                               // dwCreationFlags (0 to run immediately)
		uintptr(unsafe.Pointer(&threadId))) // lpThreadId

	if e1 != nil && e1 != syscall.Errno(0) { // Check for actual error from Call itself
		cleanup()
		return fmt.Errorf("CreateThread system call failed: %w", e1)
	}
	if hThread == 0 {
		cleanup()
		return fmt.Errorf("CreateThread failed to create thread, handle is NULL")
	}

	threadHandle := windows.Handle(hThread)
	defer windows.CloseHandle(threadHandle) // Ensure thread handle is closed eventually

	// Wait for the thread to complete.
	// If the entry point calls ExitProcess, this wait will be interrupted.
	// If the entry point is well-behaved and returns, this will allow cleanup.
	event, err := windows.WaitForSingleObject(threadHandle, windows.INFINITE)
	if err != nil {
		// Even if WaitForSingleObject fails, we should attempt cleanup if possible,
		// though the state of the created thread is unknown.
		// cleanup() // cleanup will be called at the end of the function regardless in this path
		return fmt.Errorf("WaitForSingleObject on created thread call failed: %w", err)
	}

	if event == windows.WAIT_FAILED {
		// This specific error indicates the function itself failed, not just a timeout or abandonment.
		// cleanup() // cleanup will be called at the end
		return fmt.Errorf("WaitForSingleObject on created thread failed")
	}
	
	// If WaitForSingleObject returns (e.g. thread exited normally),
	// we can proceed to cleanup mapped memory.
	// If the executable called ExitProcess(), this part might not be reached.
	cleanup()
	return nil
}
