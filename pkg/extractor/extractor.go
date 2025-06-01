package extractor

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

// Magic header to identify embedded PE data
var magicHeader = []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}

// ImageFormat represents the supported image formats
type ImageFormat int

const (
	FormatPNG ImageFormat = iota
	FormatJPEG
)

// ExtractPEFromFile extracts PE bytes from a PNG or JPEG file
func ExtractPEFromFile(imagePath string) ([]byte, error) {
	file, err := os.Open(imagePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open image file: %v", err)
	}
	defer file.Close()

	// Read file to detect format
	data, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read image file: %v", err)
	}

	format, err := detectImageFormat(data, imagePath)
	if err != nil {
		return nil, fmt.Errorf("unsupported image format: %v", err)
	}

	return ExtractPEFromReader(bytes.NewReader(data), format)
}

// ExtractPEFromBytes extracts PE bytes from PNG or JPEG image data
func ExtractPEFromBytes(imageData []byte) ([]byte, error) {
	format, err := detectImageFormat(imageData, "")
	if err != nil {
		return nil, fmt.Errorf("unsupported image format: %v", err)
	}

	return ExtractPEFromReader(bytes.NewReader(imageData), format)
}

// ExtractPEFromReader extracts PE bytes from an image reader
func ExtractPEFromReader(imgReader io.Reader, format ImageFormat) ([]byte, error) {
	// Decode the image
	var img image.Image
	var err error

	switch format {
	case FormatPNG:
		img, err = png.Decode(imgReader)
	case FormatJPEG:
		img, err = jpeg.Decode(imgReader)
	default:
		return nil, fmt.Errorf("unsupported format")
	}

	if err != nil {
		return nil, fmt.Errorf("failed to decode image: %v", err)
	}

	bounds := img.Bounds()
	width, height := bounds.Max.X, bounds.Max.Y

	// Convert to RGBA for consistent pixel access
	rgbaImg := image.NewRGBA(bounds)
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			rgbaImg.Set(x, y, img.At(x, y))
		}
	}

	// Extract the embedded data
	var extractedBits []uint8
	
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			pixel := rgbaImg.RGBAAt(x, y)
			
			// Extract from R, G, B channels
			channels := []uint8{pixel.R, pixel.G, pixel.B}
			
			for _, channel := range channels {
				// Extract the LSB
				bit := channel & 1
				extractedBits = append(extractedBits, bit)
			}
		}
	}

	// Convert bits to bytes
	var extractedBytes []byte
	for i := 0; i < len(extractedBits); i += 8 {
		if i+7 >= len(extractedBits) {
			break
		}
		
		var b uint8
		for j := 0; j < 8; j++ {
			b |= extractedBits[i+j] << (7 - j)
		}
		extractedBytes = append(extractedBytes, b)
	}

	// Debug: Print first 32 bytes to see what we're getting
	fmt.Printf("DEBUG: Extracted %d bytes total\n", len(extractedBytes))
	if len(extractedBytes) >= 32 {
		fmt.Printf("DEBUG: First 32 bytes: %x\n", extractedBytes[:32])
	}
	fmt.Printf("DEBUG: Expected magic header: %x\n", magicHeader)

	// Check for magic header
	if len(extractedBytes) < len(magicHeader)+4 {
		return nil, fmt.Errorf("insufficient data extracted - no PE found")
	}

	actualHeader := extractedBytes[:len(magicHeader)]
	fmt.Printf("DEBUG: Actual header found: %x\n", actualHeader)

	if !bytes.Equal(actualHeader, magicHeader) {
		return nil, fmt.Errorf("magic header not found - no embedded PE data")
	}

	// Extract the size
	sizeBytes := extractedBytes[len(magicHeader):len(magicHeader)+4]
	peSize := binary.LittleEndian.Uint32(sizeBytes)

	fmt.Printf("DEBUG: Detected PE size: %d bytes\n", peSize)

	// Extract the PE bytes
	dataStart := len(magicHeader) + 4
	if len(extractedBytes) < dataStart+int(peSize) {
		return nil, fmt.Errorf("insufficient PE data extracted")
	}

	peBytes := extractedBytes[dataStart:dataStart+int(peSize)]
	
	return peBytes, nil
}

// detectImageFormat determines the image format from file extension and content
func detectImageFormat(imageData []byte, imagePath string) (ImageFormat, error) {
	// First try by file extension if provided
	if imagePath != "" {
		ext := strings.ToLower(filepath.Ext(imagePath))
		switch ext {
		case ".png":
			if isValidPNG(imageData) {
				return FormatPNG, nil
			}
		case ".jpg", ".jpeg":
			if isValidJPEG(imageData) {
				return FormatJPEG, nil
			}
		}
	}

	// Try to detect by content
	if isValidPNG(imageData) {
		return FormatPNG, nil
	}
	if isValidJPEG(imageData) {
		return FormatJPEG, nil
	}

	return FormatPNG, fmt.Errorf("unsupported image format (supported: PNG, JPEG)")
}

// isValidPNG checks if the provided bytes represent a valid PNG image
func isValidPNG(data []byte) bool {
	reader := bytes.NewReader(data)
	_, err := png.Decode(reader)
	return err == nil
}

// isValidJPEG checks if the provided bytes represent a valid JPEG image
func isValidJPEG(data []byte) bool {
	reader := bytes.NewReader(data)
	_, err := jpeg.Decode(reader)
	return err == nil
}

// HasEmbeddedPE checks if the image contains embedded PE data without extracting it
func HasEmbeddedPE(imagePath string) bool {
	_, err := ExtractPEFromFile(imagePath)
	return err == nil
}

// HasEmbeddedPEFromBytes checks if the image bytes contain embedded PE data
func HasEmbeddedPEFromBytes(imageData []byte) bool {
	_, err := ExtractPEFromBytes(imageData)
	return err == nil
}

// GetEmbeddedPESize returns the size of embedded PE data without extracting it
func GetEmbeddedPESize(imagePath string) (int, error) {
	peBytes, err := ExtractPEFromFile(imagePath)
	if err != nil {
		return 0, err
	}
	return len(peBytes), nil
} 