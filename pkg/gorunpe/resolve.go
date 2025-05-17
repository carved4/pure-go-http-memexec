package gorunpe

import (
	"encoding/binary"
	"fmt"

	"gohttpmem/pkg/constants"
	"github.com/Binject/debug/pe"
	"golang.org/x/sys/windows"
)

func ResolveImports(peFile *pe.File, imageData []byte) error {
	// Find import directory
	var importDir *pe.DataDirectory

	switch oh := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if len(oh.DataDirectory) > constants.IMAGE_DIRECTORY_ENTRY_IMPORT {
			importDir = &oh.DataDirectory[constants.IMAGE_DIRECTORY_ENTRY_IMPORT]
		}
	case *pe.OptionalHeader64:
		if len(oh.DataDirectory) > constants.IMAGE_DIRECTORY_ENTRY_IMPORT {
			importDir = &oh.DataDirectory[constants.IMAGE_DIRECTORY_ENTRY_IMPORT]
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

		dllName := ReadNullTerminatedString(imageData, nameRVA)
		if dllName == "" {
			return fmt.Errorf("empty DLL name at RVA 0x%X", nameRVA)
		}

		// Load the DLL
		dll, err := windows.LoadLibrary(dllName)
		if err != nil {
			return fmt.Errorf("failed to load library %s: %w", dllName, err)
		}

		// Process imports from this DLL
		thunkRVA := originalFirstThunkRVA
		if thunkRVA == 0 {
			thunkRVA = firstThunkRVA // If no ILT, use IAT
		}

		for thunkOffset := uint32(0); ; thunkOffset += PtrSize(peFile.Machine) {
			thunkEntryRVA := thunkRVA + thunkOffset
			iatEntryRVA := firstThunkRVA + thunkOffset

			if thunkEntryRVA >= uint32(len(imageData)) || iatEntryRVA >= uint32(len(imageData)) {
				break // Out of bounds
			}

			// Read the thunk value
			var ordinal uint64
			var procRVA uint32

			if peFile.Machine == constants.IMAGE_FILE_MACHINE_AMD64 {
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
			if (peFile.Machine == constants.IMAGE_FILE_MACHINE_AMD64 && (ordinal&0x8000000000000000) != 0) ||
				(peFile.Machine != constants.IMAGE_FILE_MACHINE_AMD64 && (ordinal&0x80000000) != 0) {

				// Import by ordinal
				ord := uint16(ordinal & 0xFFFF)
				procAddr, err = windows.GetProcAddress(dll, "#"+fmt.Sprint(ord))
				if err != nil {
					return fmt.Errorf("failed to get proc address for ordinal %d in %s: %w", ord, dllName, err)
				}
			} else {
				// Import by name
				if peFile.Machine == constants.IMAGE_FILE_MACHINE_AMD64 {
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
				procName := ReadNullTerminatedString(imageData, procNameRVA)

				procAddr, err = windows.GetProcAddress(dll, procName)
				if err != nil {
					return fmt.Errorf("failed to get proc address for %s in %s: %w", procName, dllName, err)
				}
			}

			// Write the resolved address to the IAT
			if peFile.Machine == constants.IMAGE_FILE_MACHINE_AMD64 {
				binary.LittleEndian.PutUint64(imageData[iatEntryRVA:iatEntryRVA+8], uint64(procAddr))
			} else {
				binary.LittleEndian.PutUint32(imageData[iatEntryRVA:iatEntryRVA+4], uint32(procAddr))
			}
		}
	}

	return nil
}

// Helper function to read null-terminated strings from memory
func ReadNullTerminatedString(data []byte, offset uint32) string {
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
func PtrSize(machine uint16) uint32 {
	if machine == constants.IMAGE_FILE_MACHINE_AMD64 {
		return 8 // 64-bit
	}
	return 4 // 32-bit
}
