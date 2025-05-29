# Objector

JavaScript object monitor for finding exposed credentials.

## Features

- Real-time monitoring of JavaScript objects
- Detection of various credential types:
  - AWS Access Keys
  - AWS Secret Keys
  - Private Keys
  - API Keys
  - JWT Tokens
- Continuous scanning with periodic checks
- Beautiful console output with formatted results

## Installation

### Prerequisites

- Go 1.21 or later
- Chrome/Chromium browser

### Quick Install

```bash
# Clone the repository
git clone https://github.com/fractalized-cyber/objector.git
cd objector

# Install dependencies and build
go mod download
go build

# Run the tool
./objector -url http://your-target-url
```

### Using Go Install

```bash
go install github.com/fractalized-cyber/objector@latest
```

## Usage

Basic usage:
```bash
objector -url http://your-target-url
```

Options:
- `-url`: URL to monitor (required)
- `-timeout`: Monitoring timeout in seconds (default: 20s)

Example:
```bash
objector -url http://localhost:8000/test.html -timeout 30s
```

## Configuration

The tool uses `patterns.json` for configuring detection patterns. You can modify this file to add or remove patterns:

```json
{
  "patterns": [
    {
      "name": "AWS Access Key",
      "pattern": "\\b(AKIA|ASIA)[A-Z0-9]{16}\\b",
      "description": "AWS Access Key ID"
    },
    // Add more patterns here
  ],
  "ignoredPaths": [
    "performance",
    "localStorage",
    "sessionStorage",
    "indexedDB",
    "webkitStorageInfo",
    "chrome",
    "document",
    "history"
  ],
  "maxDepth": 5
}
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 