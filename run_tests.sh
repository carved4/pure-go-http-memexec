#!/bin/bash
set -e  # Exit on error

# Build the test binaries quietly
echo "Building test binaries..."
mkdir -p testdata &>/dev/null
GOOS=windows GOARCH=amd64 go build -o testdata/hello.exe testdata/helloworld.go &>/dev/null

# Function to run a test and show only the key results
function run_test_and_show_artifacts() {
    test_name=$1
    echo "----------------------------------------------------------------"
    echo "▶RUNNING $test_name"
    
    # Run the test but filter output
    (cd pkg && CGO_ENABLED=1 GOOS=windows GOARCH=amd64 go test -v . -run "^$test_name\$") > tmp_output.txt 2>&1 || { 
        echo "test failed :("
        exit 1
    }
    
    # Extract and show only the important information
    echo "test passed :)"
    
    # Get the temp directory from the test output
    temp_dir=$(grep -o "Changed working directory to temp dir: .*" tmp_output.txt | tail -1 | cut -d' ' -f7)
        
    if [ -n "$temp_dir" ]; then
        echo "temporary directory: $temp_dir"
        
        # Based on the test type, look for specific artifact file
        if [ "$test_name" == "TestExeExecution" ]; then
            artifact_file="$temp_dir/it_worked.txt"
            file_type="EXE"
        else
            artifact_file="$temp_dir/dll_worked.txt"
            file_type="DLL"
        fi
        
        # Show artifact file content if it exists
        if [ -f "$artifact_file" ]; then
            echo "📄 $file_type artifact file: $artifact_file"
            echo "📝 Content: $(cat "$artifact_file")"
        else
            echo "artifact file not found: $artifact_file"
        fi
    else
        echo "could not find temporary directory path"
    fi
    echo "----------------------------------------------------------------"
}

# Run the tests
run_test_and_show_artifacts "TestExeExecution"
run_test_and_show_artifacts "TestDllExecution"

# Clean up
rm -f tmp_output.txt

echo "All tests completed successfully!"
echo "The temporary directories were created!"
