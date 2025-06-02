package embed

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"io/ioutil"
	"path/filepath"
	"strings"
)

var MAGIC_HEADER = []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}

// ImageFormat represents the supported image formats
type ImageFormat int

const (
	FormatPNG ImageFormat = iota
	FormatJPEG
)

func EmbedPE(imagePath, pePath, outputPath string) error {
	// Read the original image
	imageData, err := ioutil.ReadFile(imagePath)
	if err != nil {
		return fmt.Errorf("failed to read image file: %v", err)
	}

	// Detect image format
	format, err := detectImageFormat(imageData, imagePath)
	if err != nil {
		return fmt.Errorf("unsupported image format: %v", err)
	}

	// Read the PE file
	peData, err := ioutil.ReadFile(pePath)
	if err != nil {
		return fmt.Errorf("failed to read PE file: %v", err)
	}

	// Embed the PE into the image
	stegoImage, err := embedPEInImage(bytes.NewReader(imageData), peData, format)
	if err != nil {
		return fmt.Errorf("failed to embed PE into image: %v", err)
	}

	// Write the output
	if err := ioutil.WriteFile(outputPath, stegoImage, 0644); err != nil {
		return fmt.Errorf("failed to write output file: %v", err)
	}

	// Verify the output is still a valid image
	if !isValidImage(stegoImage, format) {
		return fmt.Errorf("output is not a valid image - embedding failed")
	}

	formatName := "PNG"
	if format == FormatJPEG {
		formatName = "JPEG"
	}
	fmt.Printf("Embedded %d bytes of PE data into %s\n", len(peData), formatName)
	return nil
}

// detectImageFormat determines the image format from file extension and content
func detectImageFormat(imageData []byte, imagePath string) (ImageFormat, error) {
	// First try by file extension
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

	// Try to detect by content
	if isValidPNG(imageData) {
		return FormatPNG, nil
	}
	if isValidJPEG(imageData) {
		return FormatJPEG, nil
	}

	return FormatPNG, fmt.Errorf("unsupported image format (supported: PNG, JPEG)")
}

// embedPEInImage embeds PE bytes into an image using LSB steganography
func embedPEInImage(imgReader io.Reader, peBytes []byte, format ImageFormat) ([]byte, error) {
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

	// Create a new RGBA image from the original
	newImg := image.NewRGBA(bounds)
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			newImg.Set(x, y, img.At(x, y))
		}
	}

	// Prepare the data to embed: magic header + size + PE bytes
	var dataBuffer bytes.Buffer
	dataBuffer.Write(MAGIC_HEADER)
	
	// Write the size of PE bytes as uint32
	sizeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBytes, uint32(len(peBytes)))
	dataBuffer.Write(sizeBytes)
	
	// Write the actual PE bytes
	dataBuffer.Write(peBytes)
	
	dataToEmbed := dataBuffer.Bytes()

	// Check if we have enough pixels to embed the data
	totalPixels := width * height
	totalBitsNeeded := len(dataToEmbed) * 8
	if totalBitsNeeded > totalPixels*3 { // 3 channels (RGB), we skip alpha
		return nil, fmt.Errorf("image too small to embed %d bytes of data (need %d pixels, have %d)", len(peBytes), totalBitsNeeded/3, totalPixels)
	}

	// Embed the data using LSB steganography
	dataIndex := 0
	bitIndex := 0

	for y := 0; y < height && dataIndex < len(dataToEmbed); y++ {
		for x := 0; x < width && dataIndex < len(dataToEmbed); x++ {
			pixel := newImg.RGBAAt(x, y)
			
			// Embed in R, G, B channels (skip Alpha to avoid transparency issues)
			channels := [](*uint8){&pixel.R, &pixel.G, &pixel.B}
			
			for _, channel := range channels {
				if dataIndex >= len(dataToEmbed) {
					break
				}
				
				// Get the bit to embed
				bit := (dataToEmbed[dataIndex] >> (7 - bitIndex)) & 1
				
				// Clear the LSB and set our bit
				*channel = (*channel & 0xFE) | bit
				
				bitIndex++
				if bitIndex == 8 {
					bitIndex = 0
					dataIndex++
				}
			}
			
			newImg.SetRGBA(x, y, pixel)
		}
	}

	// Encode the new image to bytes
	var buf bytes.Buffer
	switch format {
	case FormatPNG:
		err = png.Encode(&buf, newImg)
	case FormatJPEG:
		// Use high quality for JPEG to minimize artifacts
		err = jpeg.Encode(&buf, newImg, &jpeg.Options{Quality: 95})
	}

	if err != nil {
		return nil, fmt.Errorf("failed to encode image: %v", err)
	}

	return buf.Bytes(), nil
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

// isValidImage checks if the provided bytes represent a valid image of the specified format
func isValidImage(data []byte, format ImageFormat) bool {
	switch format {
	case FormatPNG:
		return isValidPNG(data)
	case FormatJPEG:
		return isValidJPEG(data)
	default:
		return false
	}
} 