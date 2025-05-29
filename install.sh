#!/bin/bash

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "Go is not installed. Please install Go 1.21 or later."
    exit 1
fi

# Check Go version
GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
if [ "$(printf '%s\n' "1.21" "$GO_VERSION" | sort -V | head -n1)" != "1.21" ]; then
    echo "Go version 1.21 or later is required. Current version: $GO_VERSION"
    exit 1
fi

# Check if Chrome/Chromium is installed
if ! command -v google-chrome &> /dev/null && ! command -v chromium &> /dev/null && ! command -v chromium-browser &> /dev/null; then
    echo "Chrome or Chromium is not installed. Please install a compatible browser."
    exit 1
fi

# Create installation directory
INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"

# Install dependencies
echo "Installing dependencies..."
go mod download

# Build the application
echo "Building application..."
go build -o objector

# Install the binary
echo "Installing binary..."
mv objector "$INSTALL_DIR/"

# Add to PATH if not already present
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo "Adding $INSTALL_DIR to PATH..."
    echo "export PATH=\"\$PATH:$INSTALL_DIR\"" >> "$HOME/.bashrc"
    echo "export PATH=\"\$PATH:$INSTALL_DIR\"" >> "$HOME/.zshrc"
fi

echo "Installation complete! You can now use 'objector' from anywhere."
echo "Try running: objector -url http://your-target-url" 