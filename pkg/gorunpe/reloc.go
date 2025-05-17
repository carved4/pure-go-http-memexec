package gorunpe

import (
	"encoding/binary"
	"fmt"

	"gohttpmem/pkg/constants"
	"github.com/Binject/debug/pe"
)

func ApplyRelocations(peFile *pe.File, imageData []byte, oldBase, newBase uint64) error {
	// Find relocation directory
	var relocDir *pe.DataDirectory

	switch oh := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if len(oh.DataDirectory) > constants.IMAGE_DIRECTORY_ENTRY_BASERELOC {
			relocDir = &oh.DataDirectory[constants.IMAGE_DIRECTORY_ENTRY_BASERELOC]
		}
	case *pe.OptionalHeader64:
		if len(oh.DataDirectory) > constants.IMAGE_DIRECTORY_ENTRY_BASERELOC {
			relocDir = &oh.DataDirectory[constants.IMAGE_DIRECTORY_ENTRY_BASERELOC]
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
			case constants.IMAGE_REL_BASED_HIGHLOW: // 32-bit relocation
				if relocRVA+4 > uint32(len(imageData)) {
					return fmt.Errorf("32-bit relocation at RVA 0x%X extends beyond image boundaries", relocRVA)
				}
				addr := binary.LittleEndian.Uint32(imageData[relocRVA : relocRVA+4])
				addr = (addr - uint32(oldBase)) + uint32(newBase)
				binary.LittleEndian.PutUint32(imageData[relocRVA:relocRVA+4], addr)
			case constants.IMAGE_REL_BASED_DIR64: // 64-bit relocation
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