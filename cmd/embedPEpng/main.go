package main

import (
	"flag"
	"fmt"
	"gohttpmem/pkg/embed"
	"os"
)

func main() {
	var (
		imagePath = flag.String("i", "", "PNG image file to embed into")
		pePath    = flag.String("pe", "", "PE file to embed")
		output    = flag.String("o", "", "Output PNG file")
	)

	flag.Parse()

	if *imagePath == "" || *pePath == "" || *output == "" {
		fmt.Println("PNG PE Embedding Tool")
		fmt.Println()
		fmt.Println("Usage:")
		fmt.Printf("  %s -i <image.png> -pe <payload.exe> -o <output.png>\n", os.Args[0])
		fmt.Println()
		fmt.Println("Flags:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	fmt.Printf("Embedding %s into %s...\n", *pePath, *imagePath)

	if err := embed.EmbedPE(*imagePath, *pePath, *output); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully created %s with embedded PE\n", *output)
}
