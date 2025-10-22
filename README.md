# Grump

Grump is a CLI tool that automatically identifies and patches vulnerabilities in Go projects by using [Grype](https://github.com/anchore/grype) for vulnerability scanning and [gobump](https://github.com/chainguard-dev/gobump) for dependency updates.

## Features

- **Automatic Vulnerability Scanning**: Uses Grype library to scan Go projects for vulnerabilities
- **Automatic Patching**: Uses gobump library to update vulnerable dependencies to fixed versions
- **No External Dependencies**: Both Grype and gobump are integrated as Go libraries
- **Simple CLI**: Just point it at a Go project directory
- **Smart Filtering**: Only fixes Go modules with available patches

## Installation

### From Source

```bash
git clone https://github.com/divolgin/grump.git
cd grump
make build
```

The binary will be created at `bin/grump`.

### Install to Go bin

```bash
make install
```

This will install grump to your `$GOPATH/bin` directory.

## Usage

### Basic Usage

```bash
# Scan and fix vulnerabilities in current directory
grump .

# Scan and fix vulnerabilities in specific project
grump /path/to/project
```

### Output Formats

```bash
# Default text output (human-readable)
grump .

# JSON output for automation
grump --format json .
```

### Example Output

```
Initializing vulnerability scanner...
Scanning project at /path/to/project for vulnerabilities...
Found 3 fixable vulnerabilities:
  - github.com/ulikunitz/xz v0.5.12 → v0.5.15 (GHSA-jc7w-c686-c4v9, Medium)
  - github.com/hashicorp/go-getter v1.7.8 → v1.7.9 (GHSA-wjrx-6529-hcj3, High)
  - github.com/go-viper/mapstructure/v2 v2.3.0 → v2.4.0 (GHSA-2464-8j7c-4cjm, Medium)

Updating dependencies...
  ✓ Updated github.com/ulikunitz/xz to v0.5.15
  ✓ Updated github.com/hashicorp/go-getter to v1.7.9
  ✓ Updated github.com/go-viper/mapstructure/v2 to v2.4.0

Summary: Fixed 3 vulnerabilities
```

## How It Works

1. **Scans the project** using Grype's vulnerability database
2. **Identifies fixable vulnerabilities** - filters for Go modules that have available fixes
3. **Updates dependencies** using gobump to modify `go.mod`
4. **Runs go mod tidy** to clean up dependencies
5. **Reports results** showing what was fixed

## Exit Codes

- `0`: Success (all vulnerabilities fixed or none found)
- `1`: Some vulnerabilities could not be fixed
- `2`: Error during scan or update (invalid path, missing go.mod, etc.)

## Requirements

- Go 1.24.1 or later
- A Go project with `go.mod` file
- Internet connection (for vulnerability database updates)

## What Gets Fixed

Grump automatically fixes:
- ✅ Go module dependencies with available security patches
- ✅ Direct and indirect dependencies
- ✅ All severity levels (if a fix is available)

Grump does NOT fix:
- ❌ OS-level packages
- ❌ Container vulnerabilities
- ❌ Vulnerabilities without available fixes

## Development

### Building

```bash
make build
```

### Cleaning

```bash
make clean
```

## Architecture

Grump consists of four main components:

1. **Scanner** (`pkg/scanner`) - Grype integration for vulnerability detection
2. **Patcher** (`pkg/patcher`) - gobump integration for dependency updates
3. **Reporter** (`pkg/reporter`) - Output formatting (text and JSON)
4. **CLI** (`cmd/grump`) - Command-line interface

## Project Goals

- Simplicity: Minimal configuration, just works
- Safety: Only updates dependencies with security fixes
- Transparency: Clear reporting of what was changed
- Automation-friendly: JSON output for CI/CD integration

## License

[Add your license here]

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## Credits

- [Grype](https://github.com/anchore/grype) by Anchore - vulnerability scanning
- [gobump](https://github.com/chainguard-dev/gobump) by Chainguard - dependency bumping

