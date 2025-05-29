.PHONY: build clean install test

# Build the application
build:
	go build -o objector

# Clean build artifacts
clean:
	rm -f objector

# Install dependencies
deps:
	go mod download

# Install the application
install: build
	mv objector $(GOPATH)/bin/

# Run tests
test:
	go test ./...

# Run the application
run: build
	./objector

# Create a release build
release: clean
	GOOS=linux GOARCH=amd64 go build -o objector-linux-amd64
	GOOS=darwin GOARCH=amd64 go build -o objector-darwin-amd64
	GOOS=darwin GOARCH=arm64 go build -o objector-darwin-arm64
	GOOS=windows GOARCH=amd64 go build -o objector-windows-amd64.exe

# Default target
all: deps build 