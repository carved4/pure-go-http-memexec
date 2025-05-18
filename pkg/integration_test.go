package pkg_test

import (
	"fmt"
	"gohttpmem/pkg/gorundll"
	"gohttpmem/pkg/gorunpe"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)	

func TestExeExecution(t *testing.T) {
	// Find the correct path to the test binaries
	// Get current working directory
	pwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}
	fmt.Printf("Current working directory: %s\n", pwd)

	// Try to find the testdata directory by walking up from the current directory
	exePath := filepath.Join(pwd, "testdata", "hello.exe")
	if _, err := os.Stat(exePath); os.IsNotExist(err) {
		// Try one level up
		exePath = filepath.Join(pwd, "..", "testdata", "hello.exe")
		if _, err := os.Stat(exePath); os.IsNotExist(err) {
			// Try the absolute path directly
			exePath = filepath.Join("/c:/Users/owen/Desktop/github - gohttpmemexec/pure-go-http-memexec/testdata/hello.exe")
		}
	}

	fmt.Printf("Using EXE path: %s\n", exePath)

	// Check if the test binary exists
	_, err = os.Stat(exePath)
	if os.IsNotExist(err) {
		t.Skip("Test EXE not found at path: " + exePath)
	}

	// 1. Load test EXE bytes
	exeBytes, err := os.ReadFile(exePath)
	if err != nil {
		t.Fatalf("Failed to read test EXE: %v", err)
	}
	fmt.Printf("Successfully loaded %d bytes from EXE\n", len(exeBytes))

	// 2. Serve via HTTP
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(exeBytes)
	}))
	defer ts.Close()

	// 3. Use a fresh temp dir
	tmpDir := t.TempDir()
	origWD, _ := os.Getwd()
	defer os.Chdir(origWD)
	os.Chdir(tmpDir)
	fmt.Printf("Changed working directory to temp dir: %s\n", tmpDir)

	// 4. Run EXE in memory
	fmt.Println("About to execute EXE in memory...")
	err = gorunpe.ExecuteInMemory(exeBytes)
	if err != nil {
		t.Fatalf("ExecuteInMemory failed: %v", err)
	}
	fmt.Println("EXE execution completed")

	// 5. List files in temp dir to help debug
	files, err := os.ReadDir(tmpDir)
	if err != nil {
		fmt.Printf("Error listing directory: %v\n", err)
	} else {
		fmt.Println("Files in temp directory:")
		for _, file := range files {
			fmt.Printf("  - %s\n", file.Name())
		}
	}

	// 6. Verify side effect
	filePath := filepath.Join(tmpDir, "it_worked.txt")
	fmt.Printf("Looking for file at: %s\n", filePath)
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("missing it_worked.txt: %v", err)
	}
	
	content := string(data)
	fmt.Printf("File content: %q\n", content)
	if content != "EXE execution successful" {
		t.Fatalf("unexpected contents: %q", content)
	}
}

func TestDllExecution(t *testing.T) {
	fmt.Println("=== Starting DLL Execution Test ===")
	
	// Get current working directory
	pwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}
	fmt.Printf("Current working directory: %s\n", pwd)

	// Try to find the testdata directory by walking up from the current directory
	dllPath := filepath.Join(pwd, "..", "testdata", "hello.dll")
	fmt.Printf("Using DLL path: %s\n", dllPath)

	// Check if the test binary exists
	_, err = os.Stat(dllPath)
	if os.IsNotExist(err) {
		t.Skip("Test DLL not found at path: " + dllPath)
	}

	// 1. Load test DLL bytes
	dllBytes, err := os.ReadFile(dllPath)
	if err != nil {
		t.Fatalf("Failed to read test DLL: %v", err)
	}
	fmt.Printf("Successfully loaded %d bytes from DLL\n", len(dllBytes))

	// 2. Serve via HTTP
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(dllBytes)
	}))
	defer ts.Close()

	// 3. Use a fresh temp dir
	tmpDir := t.TempDir()
	origWD, _ := os.Getwd()
	defer os.Chdir(origWD)
	os.Chdir(tmpDir)
	fmt.Printf("Changed working directory to temp dir: %s\n", tmpDir)

	// 4. Load and execute DLL
	fmt.Println("About to load DLL into memory...")
	dllHandle, err := gorundll.LoadDLLInMemory(dllBytes)
	if err != nil {
		t.Fatalf("LoadDLLInMemory failed: %v", err)
	}
	fmt.Printf("DLL loaded at handle: %x\n", dllHandle)

	// 5. Call the exported function
	fmt.Println("About to call DLL export 'TestDllFunc'...")
	ret, err := gorundll.CallExportWithNoArgs(dllHandle, "TestDllFunc")
	if err != nil {
		t.Fatalf("CallExportWithNoArgs failed: %v", err)
	}
	fmt.Printf("DLL function call returned: %d\n", ret)

	// 6. Verify side effect
	filePath := filepath.Join(tmpDir, "dll_worked.txt")
	fmt.Printf("Looking for file at: %s\n", filePath)
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("missing dll_worked.txt: %v", err)
	}
	
	content := string(data)
	fmt.Printf("File content: %q\n", content)
	if content != "DLL execution successful" {
		t.Fatalf("unexpected contents: %q", content)
	}

	// 7. Clean up
	fmt.Println("Freeing DLL from memory...")
	err = gorundll.FreeDLLFromMemory(dllHandle)
	if err != nil {
		t.Fatalf("FreeDLLFromMemory failed: %v", err)
	}
	fmt.Println("DLL freed successfully")
} 