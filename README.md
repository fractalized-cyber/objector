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
- Custom header support for authenticated requests

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
./objector -u [url]
```

### Using Go Install

```bash
go install github.com/fractalized-cyber/objector@latest
```

## Usage

Basic usage:
```bash
objector -u [url]
```

Options:
- `-u`, `--url`: URL to monitor (required)
- `--timeout`: Monitoring timeout in seconds (default: 20s)
- `--headers`: Headers to include in requests (format: 'HEADER: VALUE,HEADER2: VALUE2')
- `--string`: Custom string to search for (if provided, ignores default patterns)
- `--help`, `-h`: Show help message

Examples:
```bash
# Basic usage
objector -u [url]

# With custom timeout
objector -u [url] --timeout 30s

# With custom headers
objector -u [url] --headers "Authorization: Bearer token,Cookie: session=abc123"

# With custom string search
objector -u [url] --string "my-secret-key"
```

If no parameters are provided, or if you use `--help`, a detailed help message will be shown.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 