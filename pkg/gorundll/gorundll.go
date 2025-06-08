package gorundll

import (
    "bytes"
    "fmt"
    "sync"
    "time"
    "unsafe"

    "github.com/Binject/debug/pe"
    "github.com/carved4/go-direct-syscall"

    "gohttpmem/pkg/constants"
    "gohttpmem/pkg/gorunpe"
)

var (
    loadedDLLs = make(map[uintptr]*loadedDLL)
    dllsMu     sync.Mutex
)

type loadedDLL struct {
    peFile     *pe.File
    entryPoint uintptr
    funcTable  unsafe.Pointer
}

// LoadDLLInMemory loads a DLL from raw bytes into memory using Binject/debug/pe.
// It applies relocations, resolves imports, sets section protections,
// executes TLS callbacks, and calls DllMain(DLL_PROCESS_ATTACH).
func LoadDLLInMemory(dllBytes []byte) (uintptr, error) {
    // Parse PE file
    reader := bytes.NewReader(dllBytes)
    peFile, err := pe.NewFile(reader)
    if err != nil {
        return 0, fmt.Errorf("PE parse error: %w", err)
    }

    // Extract header info
    var sizeOfHeaders, sizeOfImage uint32
    var imageBase uint64
    var entryRVA uint32
    switch oh := peFile.OptionalHeader.(type) {
    case *pe.OptionalHeader32:
        sizeOfHeaders = oh.SizeOfHeaders
        sizeOfImage = oh.SizeOfImage
        imageBase = uint64(oh.ImageBase)
        entryRVA = oh.AddressOfEntryPoint
    case *pe.OptionalHeader64:
        sizeOfHeaders = oh.SizeOfHeaders
        sizeOfImage = oh.SizeOfImage
        imageBase = oh.ImageBase
        entryRVA = oh.AddressOfEntryPoint
    default:
        return 0, fmt.Errorf("unsupported optional header type")
    }

    // Validate sizes
    if uint32(len(dllBytes)) < sizeOfHeaders {
        return 0, fmt.Errorf("payload too small: %d < headers %d", len(dllBytes), sizeOfHeaders)
    }
    const maxSize = 512 * 1024 * 1024
    if sizeOfImage == 0 || sizeOfImage > maxSize {
        return 0, fmt.Errorf("invalid image size: %d", sizeOfImage)
    }

    // Allocate memory using NtAllocateVirtualMemory with retry logic
    var baseAddr uintptr
    var regionSize uintptr
    const maxRetries = 10
    const baseDelay = 10 * time.Millisecond
    

    
    for attempt := 0; attempt < maxRetries; attempt++ {
        baseAddr = 0 // Reset base address for each attempt, let system choose
        regionSize = uintptr(sizeOfImage)
        
        // Small delay before each attempt (except the first)
        if attempt > 0 {        
            delay := time.Duration(attempt) * baseDelay
            time.Sleep(delay)
        }
        
        status, err := winapi.NtAllocateVirtualMemory(
            winapi.CURRENT_PROCESS,                          // ProcessHandle
            &baseAddr,                                       // BaseAddress (NULL = let system choose)
            0,                                               // ZeroBits
            &regionSize,                                     // RegionSize
            winapi.MEM_RESERVE|winapi.MEM_COMMIT,            // AllocationType
            winapi.PAGE_READWRITE)                           // Protect

        if err != nil {
            // System-level error, don't retry
            return 0, fmt.Errorf("NtAllocateVirtualMemory failed: %w", err)
        }
        
        // Check for success
        if winapi.IsNTStatusSuccess(status) && baseAddr != 0 {
            // Success case: we got a valid base address
            break
        }
        
        // Handle specific retryable errors
        const STATUS_CONFLICTING_ADDRESSES = 0xc0000018
        const STATUS_INVALID_ADDRESS = 0xc0000141
        
        if status == STATUS_CONFLICTING_ADDRESSES || status == STATUS_INVALID_ADDRESS {
            fmt.Printf("Attempt %d: Memory conflict (status 0x%x), retrying...\n", attempt+1, status)
            if attempt == maxRetries-1 {
                return 0, fmt.Errorf("NtAllocateVirtualMemory failed after %d attempts with status: 0x%x", maxRetries, status)
            }
            continue // Retry
        }
        
        // For other non-success statuses, fail immediately
        if !winapi.IsNTStatusSuccess(status) {
            return 0, fmt.Errorf("NtAllocateVirtualMemory failed with status: 0x%x", status)
        }
        
        // If we got status success but null base address, retry
        if baseAddr == 0 {
            fmt.Printf("Attempt %d: Got NULL base address despite success, retrying...\n", attempt+1)
            if attempt == maxRetries-1 {
                return 0, fmt.Errorf("NtAllocateVirtualMemory returned NULL base address after %d attempts", maxRetries)
            }
        }
    }

    success := false
    defer func() {
        if !success {
            winapi.NtFreeVirtualMemory(winapi.CURRENT_PROCESS, &baseAddr, &regionSize, winapi.MEM_RELEASE)
        }
    }()

    // Create slice over memory region
    region := unsafe.Slice((*byte)(unsafe.Pointer(baseAddr)), sizeOfImage)

    // Copy headers
    copy(region[:sizeOfHeaders], dllBytes[:sizeOfHeaders])

    // Copy sections
    for _, sec := range peFile.Sections {
        if sec.VirtualSize == 0 {
            continue
        }
        data, err := sec.Data()
        if err != nil {
            return 0, fmt.Errorf("section %s data error: %w", sec.Name, err)
        }
        va := sec.VirtualAddress
        copy(region[va:va+uint32(len(data))], data)
    }

    // Apply relocations if base changed
    fmt.Printf("DEBUG: Starting relocations...\n")
    if uint64(baseAddr) != imageBase {
        if err := gorunpe.ApplyRelocations(peFile, region, imageBase, uint64(baseAddr)); err != nil {
            return 0, fmt.Errorf("relocations failed: %w", err)
        }
    }
    fmt.Printf("DEBUG: Relocations completed\n")

    // Resolve imports
    fmt.Printf("DEBUG: Starting import resolution...\n")
    if err := gorunpe.ResolveImports(peFile, baseAddr); err != nil {
        return 0, fmt.Errorf("import resolution failed: %w", err)
    }
    fmt.Printf("DEBUG: Import resolution completed\n")

    // Set section protections
    for _, sec := range peFile.Sections {
        if sec.VirtualSize == 0 {
            continue
        }
        ch := sec.Characteristics
        var prot uintptr = winapi.PAGE_READONLY
        if ch&constants.IMAGE_SCN_MEM_EXECUTE != 0 {
            if ch&constants.IMAGE_SCN_MEM_WRITE != 0 {
                prot = winapi.PAGE_EXECUTE_READWRITE
            } else {
                prot = winapi.PAGE_EXECUTE_READ
            }
        } else if ch&constants.IMAGE_SCN_MEM_WRITE != 0 {
            prot = winapi.PAGE_READWRITE
        }
        addr := baseAddr + uintptr(sec.VirtualAddress)
        size := uintptr(sec.VirtualSize)
        // Align to page
        size = (size + uintptr(constants.PAGE_SIZE - 1)) & ^uintptr(constants.PAGE_SIZE - 1)
        var oldProt uintptr
        
        // Debug print for section protection
        fmt.Printf("Setting section %s protection: 0x%x, addr: %x, size: %x\n", 
            sec.Name, prot, addr, size)
            
        status, err := winapi.NtProtectVirtualMemory(
            winapi.CURRENT_PROCESS,  // ProcessHandle
            &addr,                   // BaseAddress
            &size,                   // RegionSize
            prot,                    // NewProtect
            &oldProt)                // OldProtect
            
        if err != nil {
            return 0, fmt.Errorf("NtProtectVirtualMemory %s failed: %w", sec.Name, err)
        }
        if !winapi.IsNTStatusSuccess(status) {
            return 0, fmt.Errorf("NtProtectVirtualMemory %s failed with status: 0x%x", sec.Name, status)
        }
        
        fmt.Printf("  Section %s protection changed from 0x%x to 0x%x\n", 
            sec.Name, oldProt, prot)
    }

    // Locate the exception directory - SEH registration is important for performance
    var funcTable unsafe.Pointer
    // Check if OptionalHeader is available and is of type *pe.OptionalHeader64
    // IMAGE_DIRECTORY_ENTRY_EXCEPTION is only present in 64-bit PE files
    if oh, ok := peFile.OptionalHeader.(*pe.OptionalHeader64); ok {
        excDir := oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXCEPTION]
        if excDir.VirtualAddress != 0 && excDir.Size > 0 {
            base := baseAddr
            // Pointer to first RUNTIME_FUNCTION
            funcTable = unsafe.Pointer(base + uintptr(excDir.VirtualAddress))
            // Each RUNTIME_FUNCTION is 12 bytes on x64
            const runtimeFunctionSize = 12
            count := uintptr(excDir.Size) / runtimeFunctionSize

            fmt.Printf("Registering %d exception handlers at 0x%x\n", count, uintptr(funcTable))

            // RtlAddFunctionTable is already in NTDLL (not kernel32) so it's low-level enough
            // Use DirectSyscall to call it for maximum stealth
            r1, err := winapi.DirectSyscall("RtlAddFunctionTable",
                uintptr(funcTable),
                count,
                uintptr(base))
                
            if err != nil {
                return 0, fmt.Errorf("RtlAddFunctionTable syscall failed: %w", err)
            }
            // According to MSDN, RtlAddFunctionTable returns a non-zero value on success.
            if r1 == 0 {
                 return 0, fmt.Errorf("RtlAddFunctionTable failed")
            }
            fmt.Printf("Successfully registered exception handlers via RtlAddFunctionTable\n")
        }
    }

    // Use the specialized DLL TLS callback handler instead of the generic one
    fmt.Printf("DEBUG: Starting TLS callbacks...\n")
    if err := gorunpe.ExecuteDLLTLSCallbacks(peFile, baseAddr); err != nil {
        return 0, fmt.Errorf("DLL TLS callbacks failed: %w", err)
    }
    fmt.Printf("DEBUG: TLS callbacks completed\n")

    // Call DllMain(DLL_PROCESS_ATTACH)
    fmt.Printf("DEBUG: Starting DllMain...\n")
    if entryRVA != 0 {
        dllMain := baseAddr + uintptr(entryRVA)
        r1, err := winapi.DirectSyscall("", dllMain, baseAddr, constants.DLL_PROCESS_ATTACH, 0)
        if err != nil {
            return 0, fmt.Errorf("DllMain syscall failed: %w", err)
        }
        if r1 == 0 {
            return 0, fmt.Errorf("DllMain returned FALSE")
        }
    }
    fmt.Printf("DEBUG: DllMain completed\n")

    success = true
    // Track module
    dllsMu.Lock()
    loadedDLLs[baseAddr] = &loadedDLL{peFile: peFile, entryPoint: baseAddr + uintptr(entryRVA), funcTable: funcTable}
    dllsMu.Unlock()

    return baseAddr, nil
}

// GetProcAddressFromMemoryDLL retrieves the address of an exported function by name.
func GetProcAddressFromMemoryDLL(handle uintptr, name string) (uintptr, error) {
    dllsMu.Lock()
    info, ok := loadedDLLs[handle]
    dllsMu.Unlock()
    if !ok {
        return 0, fmt.Errorf("invalid module handle: %x", handle)
    }

    // Get export directory entry
    var exDir pe.DataDirectory
    switch oh := info.peFile.OptionalHeader.(type) {
    case *pe.OptionalHeader32:
        exDir = oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
    case *pe.OptionalHeader64:
        exDir = oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
    default:
        return 0, fmt.Errorf("unsupported optional header type")
    }
    if exDir.VirtualAddress == 0 || exDir.Size == 0 {
        return 0, fmt.Errorf("no export directory")
    }
    base := handle
    exp := (*pe.ExportDirectory)(unsafe.Pointer(base + uintptr(exDir.VirtualAddress)))

    names := base + uintptr(exp.NameTableAddr)
    ords := base + uintptr(exp.OrdinalTableAddr)
    funcs := base + uintptr(exp.AddressTableAddr)

    for i := uint32(0); i < exp.NumberOfNames; i++ {
        nameRVA := *(*uint32)(unsafe.Pointer(names + uintptr(i*4)))
        // Convert name from C string to Go string manually
        namePtr := (*byte)(unsafe.Pointer(base + uintptr(nameRVA)))
        var funcName string
        nameBytes := unsafe.Slice(namePtr, 256) // Assume max name length of 256
        for j, b := range nameBytes {
            if b == 0 {
                funcName = string(nameBytes[:j])
                break
            }
        }
        if funcName == name {
            ordinal := *(*uint16)(unsafe.Pointer(ords + uintptr(i*2)))
            rva := *(*uint32)(unsafe.Pointer(funcs + uintptr(uint32(ordinal)*4)))
            return base + uintptr(rva), nil
        }
    }
    return 0, fmt.Errorf("export %s not found", name)
}

// GetProcAddressByOrdinalFromMemoryDLL retrieves the address of an export by ordinal.
func GetProcAddressByOrdinalFromMemoryDLL(handle uintptr, ordinal uint16) (uintptr, error) {
    dllsMu.Lock()
    info, ok := loadedDLLs[handle]
    dllsMu.Unlock()
    if !ok {
        return 0, fmt.Errorf("invalid module handle: %x", handle)
    }

    var exDir pe.DataDirectory
    switch oh := info.peFile.OptionalHeader.(type) {
    case *pe.OptionalHeader32:
        exDir = oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
    case *pe.OptionalHeader64:
        exDir = oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
    default:
        return 0, fmt.Errorf("unsupported optional header type")
    }
    if exDir.VirtualAddress == 0 || exDir.Size == 0 {
        return 0, fmt.Errorf("no export directory")
    }
    base := handle
    exp := (*pe.ExportDirectory)(unsafe.Pointer(base + uintptr(exDir.VirtualAddress)))

    baseOrd := exp.OrdinalBase
    if uint32(ordinal) < baseOrd || uint32(ordinal) >= baseOrd+exp.NumberOfFunctions {
        return 0, fmt.Errorf("ordinal %d out of range", ordinal)
    }
    funcs := base + uintptr(exp.AddressTableAddr)
    rva := *(*uint32)(unsafe.Pointer(funcs + uintptr((uint32(ordinal)-baseOrd)*4)))
    return base + uintptr(rva), nil
}

// FreeDLLFromMemory frees a DLL loaded with LoadDLLInMemory by calling DllMain(DLL_PROCESS_DETACH) and freeing memory.
func FreeDLLFromMemory(handle uintptr) error {
    dllsMu.Lock()
    info, ok := loadedDLLs[handle]
    if ok {
        delete(loadedDLLs, handle)
    }
    dllsMu.Unlock()

    if ok && info.entryPoint != 0 {
        winapi.DirectSyscall("", info.entryPoint, handle, constants.DLL_PROCESS_DETACH, 0)
    }

    // Exception handler cleanup - when using NtSetInformationProcess directly,
    // the cleanup is automatically handled when the process memory is freed
    // No explicit unregistration needed since we're freeing the entire memory region
    if ok && info.funcTable != nil {
        fmt.Printf("Exception handlers at 0x%x will be cleaned up automatically with memory deallocation\n", uintptr(info.funcTable))
    }

    // Free memory using NtFreeVirtualMemory
    baseAddr := handle
    regionSize := uintptr(0) // Will be filled by the function
    status, err := winapi.NtFreeVirtualMemory(winapi.CURRENT_PROCESS, &baseAddr, &regionSize, winapi.MEM_RELEASE)
    if err != nil {
        return fmt.Errorf("NtFreeVirtualMemory failed: %w", err)
    }
    if !winapi.IsNTStatusSuccess(status) {
        return fmt.Errorf("NtFreeVirtualMemory failed with status: 0x%x", status)
    }
    return nil
}

// CallExportWithNoArgs calls an exported function that takes no arguments.
// This ensures proper calling convention is used on x64 platforms.
func CallExportWithNoArgs(handle uintptr, name string) (uintptr, error) {
    addr, err := GetProcAddressFromMemoryDLL(handle, name)
    if err != nil {
        return 0, fmt.Errorf("failed to get proc address: %w", err)
    }
    
    fmt.Printf("Calling export %s at address %x with 0 arguments\n", name, addr)
    // Use DirectSyscall with 0 arguments for the actual function
    r1, err := winapi.DirectSyscall("", addr)
    if err != nil {
        return r1, fmt.Errorf("export call failed: %w", err)
    }
    return r1, nil
}