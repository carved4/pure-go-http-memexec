.PHONY: build-test-binaries clean test

build-test-binaries:
	@echo "Building test EXE..."
	GOOS=windows GOARCH=amd64 go build -o testdata/hello.exe testdata/helloworld.go
	@echo "Building test DLL..."
	GOOS=windows GOARCH=amd64 CGO_ENABLED=1 go build -buildmode=c-shared -o testdata/hello.dll testdata/hellodll.go

clean:
	rm -f testdata/hello.exe testdata/hello.dll testdata/*.h

test: build-test-binaries
	go test ./... 