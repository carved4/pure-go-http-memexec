package gorundll

import (
    "bytes"
    "fmt"
    "sync"
    "unsafe"

    "github.com/Binject/debug/pe"
    "golang.org/x/sys/windows"
    "syscall"

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

    // Allocate memory
    baseAddr, allocErr := windows.VirtualAlloc(0, uintptr(sizeOfImage),
        windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_READWRITE)
    if allocErr != nil || baseAddr == 0 {
        return 0, fmt.Errorf("memory allocation failed: %v", allocErr)
    }
    success := false
    defer func() {
        if !success {
            windows.VirtualFree(baseAddr, 0, windows.MEM_RELEASE)
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
    if uint64(baseAddr) != imageBase {
        if err := gorunpe.ApplyRelocations(peFile, region, imageBase, uint64(baseAddr)); err != nil {
            return 0, fmt.Errorf("relocations failed: %w", err)
        }
    }

    // Resolve imports
    if err := gorunpe.ResolveImports(peFile, baseAddr); err != nil {
        return 0, fmt.Errorf("import resolution failed: %w", err)
    }

    // Set section protections
    for _, sec := range peFile.Sections {
        if sec.VirtualSize == 0 {
            continue
        }
        ch := sec.Characteristics
        var prot uint32 = windows.PAGE_READONLY
        if ch&constants.IMAGE_SCN_MEM_EXECUTE != 0 {
            if ch&constants.IMAGE_SCN_MEM_WRITE != 0 {
                prot = windows.PAGE_EXECUTE_READWRITE
            } else {
                prot = windows.PAGE_EXECUTE_READ
            }
        } else if ch&constants.IMAGE_SCN_MEM_WRITE != 0 {
            prot = windows.PAGE_READWRITE
        }
        addr := baseAddr + uintptr(sec.VirtualAddress)
        size := uintptr(sec.VirtualSize)
        // Align to page
        size = (size + uintptr(constants.PAGE_SIZE - 1)) & ^uintptr(constants.PAGE_SIZE - 1)
        var old uint32
        
        // Debug print for section protection
        fmt.Printf("Setting section %s protection: 0x%x, addr: %x, size: %x\n", 
            sec.Name, prot, addr, size)
            
        if e := windows.VirtualProtect(addr, size, prot, &old); e != nil {
            return 0, fmt.Errorf("VirtualProtect %s failed: %w", sec.Name, e)
        }
        
        // Verify protections were set correctly
        var memInfo windows.MemoryBasicInformation
        if e := windows.VirtualQuery(addr, &memInfo, unsafe.Sizeof(memInfo)); e == nil {
            fmt.Printf("  Verified protection for %s: expected 0x%x, got 0x%x\n", 
                sec.Name, prot, memInfo.Protect)
        }
    }

    // Locate the exception directory
    var funcTable unsafe.Pointer
    // Check if OptionalHeader is available and is of type *pe.OptionalHeader64
    // IMAGE_DIRECTORY_ENTRY_EXCEPTION is only present in 64-bit PE files
    if oh, ok := peFile.OptionalHeader.(*pe.OptionalHeader64); ok {
        excDir := oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXCEPTION]
        if excDir.VirtualAddress != 0 && excDir.Size > 0 {
            base := baseAddr
            // Pointer to first RUNTIME_FUNCTION
            funcTable = unsafe.Pointer(base + uintptr(excDir.VirtualAddress))
            entrySize := unsafe.Sizeof(windows.RUNTIME_FUNCTION{})
            count := uintptr(excDir.Size) / entrySize

            // Call RtlAddFunctionTable(table, count, ImageBase)
            ntdll := windows.NewLazySystemDLL("ntdll.dll")
            addFT := ntdll.NewProc("RtlAddFunctionTable")
            r1, _, e1 := addFT.Call(
                uintptr(funcTable),
                count,
                uintptr(base),
            )
            // According to MSDN, RtlAddFunctionTable returns a non-zero value on success.
            // So r1 == 0 means failure. The user's original code had this inverted.
            if r1 == 0 {
                 return 0, fmt.Errorf("RtlAddFunctionTable failed: %v", e1)
            }
        }
    }

    // Use the specialized DLL TLS callback handler instead of the generic one
    if err := gorunpe.ExecuteDLLTLSCallbacks(peFile, baseAddr); err != nil {
        return 0, fmt.Errorf("DLL TLS callbacks failed: %w", err)
    }
    

    // Call DllMain(DLL_PROCESS_ATTACH)
    if entryRVA != 0 {
        dllMain := baseAddr + uintptr(entryRVA)
        r1, _, ec := syscall.Syscall(dllMain, 3, baseAddr, constants.DLL_PROCESS_ATTACH, 0)
        if ec != 0 {
            return 0, fmt.Errorf("DllMain failed: %v", ec)
        }
        if r1 == 0 {
            return 0, fmt.Errorf("DllMain returned FALSE")
        }
    }

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
        funcName := windows.BytePtrToString((*byte)(unsafe.Pointer(base + uintptr(nameRVA))))
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
        syscall.Syscall(info.entryPoint, 3, handle, constants.DLL_PROCESS_DETACH, 0)
    }

    // RtlDeleteFunctionTable(funcTable)
    // Only call if funcTable was registered (i.e., not nil and on 64-bit)
    if ok && info.funcTable != nil {
        ntdll := windows.NewLazySystemDLL("ntdll.dll")
        delFT := ntdll.NewProc("RtlDeleteFunctionTable")
        // According to MSDN, RtlDeleteFunctionTable returns a BOOLEAN (non-zero for success, 0 for failure).
        // We don't typically check the return for cleanup functions like this unless debugging.
        delFT.Call(uintptr(info.funcTable))
    }

    if err := windows.VirtualFree(handle, 0, windows.MEM_RELEASE); err != nil {
        return fmt.Errorf("VirtualFree failed: %w", err)
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
    // Use syscall.Syscall with 0 arguments for the actual function
    r1, _, errno := syscall.Syscall(addr, 0, 0, 0, 0)

    // errno is of type syscall.Errno (uintptr).
    // A value of 0 typically indicates success from the syscall itself.
    // If errno is not 0, it might be an actual error or a success code
    // that Go's syscall layer wraps as a non-nil error object.
    if errno != 0 { // Check if errno is not numerically zero
        // If it's not zero, check if it's the specific "success" message.
        // If it is this message, we treat it as success (return nil error).
        // Otherwise, it's a real error.
        if errno.Error() == "The operation completed successfully." {
            return r1, nil // Success
        }
        return r1, errno // Actual error
    }
    // If errno was 0, it's success.
    return r1, nil
}