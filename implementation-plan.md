# Grump - Implementation Plan

## Project Overview

**Grump** is a minimal CLI tool that automates the process of identifying and patching vulnerabilities in Go projects by integrating Grype (vulnerability scanner) and gobump (dependency updater) as Go libraries.

## Architecture

### Design Decision: Library Integration

**Grump uses Grype and gobump as Go library dependencies rather than external binaries.**

**Benefits:**
- **Single Binary**: Users only need to install grump, no additional tools required
- **Type Safety**: Direct API access with compile-time type checking
- **Performance**: No subprocess overhead, faster execution
- **Simplified Deployment**: No need to manage multiple tool installations
- **Native Data Structures**: Use Grype's and gobump's native types directly

### Core Components

1. **CLI Interface** (`cmd/grump/main.go`)
   - Single command: scan and fix a directory
   - Minimal arguments: just the path to the Go project

2. **Scanner Module** (`pkg/scanner`)
   - Grype library integration
   - Uses Grype's native data structures (e.g., `grype.Matches`)

3. **Patcher Module** (`pkg/patcher`)
   - gobump library integration  
   - Updates dependencies to fix versions

4. **Reporter Module** (`pkg/reporter`)
   - Simple text and JSON output
   - Reports what was fixed

## Grype Output Structure

Based on the example scan output, Grype returns:

```json
{
  "matches": [
    {
      "vulnerability": {
        "id": "GHSA-...",
        "severity": "Medium|High|Critical",
        "fix": {
          "versions": ["0.5.15"],
          "state": "fixed"
        }
      },
      "matchDetails": [
        {
          "searchedBy": {
            "package": {
              "name": "github.com/ulikunitz/xz",
              "version": "v0.5.12"
            }
          },
          "fix": {
            "suggestedVersion": "0.5.15"
          }
        }
      ],
      "artifact": {
        "name": "github.com/ulikunitz/xz",
        "version": "v0.5.12",
        "type": "go-module"
      }
    }
  ]
}
```

**Key Observations:**
- CVE-to-package mapping is already done by Grype
- Suggested fix version is in `matchDetails[0].fix.suggestedVersion`
- Package name and current version are in `artifact`
- **Filter criteria**: `vulnerability.fix.state == "fixed"` AND `artifact.type == "go-module"`
  - Only process Go modules (not OS packages, containers, etc.)
  - Only process vulnerabilities that have a fix available

## Implementation Phases

### Phase 1: Project Setup
**Duration: 1 day**

- [ ] Create project structure
- [ ] Initialize Go module
  ```bash
  go mod init github.com/divolgin/grump
  go get github.com/anchore/grype
  go get github.com/chainguard-dev/gobump
  ```
- [ ] Create Makefile for building
- [ ] Create basic CLI skeleton

**Deliverables:**
- Working project structure
- Makefile with build target
- Basic CLI entry point

### Phase 2: Grype Integration
**Duration: 2-3 days**

- [ ] Study Grype library API
  - Look at how Grype CLI uses the library internally
  - Understand `grype.GetScan()` or equivalent function
  - Find data structures for scan results
- [ ] Implement scanner module
  - Initialize Grype scanner
  - Scan Go project directory
  - Return Grype's native match results
- [ ] Parse fixable vulnerabilities
  - Filter matches where `fix.state == "fixed"` AND `artifact.type == "go-module"`
  - Extract package name and suggested version
  - Build list of packages to update

**Deliverables:**
- Working Grype library integration
- List of fixable vulnerabilities with target versions

### Phase 3: gobump Integration  
**Duration: 2-3 days**

- [ ] Study gobump library API
  - Understand how to programmatically update dependencies
  - Find function to bump specific package to specific version
  - Understand go mod tidy integration
- [ ] Implement patcher module
  - Update each package to its fix version
  - Use gobump to modify go.mod
  - Run go mod tidy (via gobump or directly)
- [ ] Handle errors gracefully
  - If update fails, continue with next package
  - Report which updates succeeded/failed

**Deliverables:**
- Working gobump library integration
- Ability to update multiple dependencies

### Phase 4: Integration and Reporting
**Duration: 1-2 days**

- [ ] Connect scanner and patcher
  - Pass fixable vulnerabilities to patcher
  - Update all fixable packages
- [ ] Implement simple reporting
  - Text output: list of fixed vulnerabilities
  - JSON output: structured results
- [ ] Add proper error handling
- [ ] Polish CLI experience

**Deliverables:**
- Working end-to-end flow
- Clear reporting of actions taken

## Technical Specifications

### Dependencies

```go
// Core Go dependencies
github.com/anchore/grype         // Vulnerability scanning
github.com/chainguard-dev/gobump // Dependency bumping
golang.org/x/mod                 // Go module parsing (may be transitive)
```

### CLI Interface Design

```bash
# Basic usage
grump <path>                    # Scan and auto-fix vulnerabilities in project

# Examples
grump .                         # Fix current directory
grump /path/to/project          # Fix specified project
grump . > report.json           # Save JSON output to file
```

**Output Modes:**
- Default: Human-readable text showing what was fixed
- Set via environment or simple flag if needed

**Exit Codes:**
- 0: Success (all vulnerabilities fixed or none found)
- 1: Some vulnerabilities could not be fixed
- 2: Error during scan or update

### Data Flow

```
1. User invokes: grump <path>
2. Validate path contains go.mod
3. Initialize Grype scanner
4. Run Grype scan on project (using library API)
5. Parse scan results (use Grype's native types)
6. Extract fixable vulnerabilities:
   - Filter matches where vulnerability.fix.state == "fixed" AND artifact.type == "go-module"
   - Extract package name from artifact.name
   - Extract target version from matchDetails[0].fix.suggestedVersion
7. For each fixable vulnerability:
   - Use gobump to update package to target version
   - Report success or failure
8. Display summary report
9. Exit with appropriate code
```

### Key Data Structures

**Use Grype's Native Types:**
```go
// From github.com/anchore/grype
type Match struct {
    Vulnerability Vulnerability
    MatchDetails  []MatchDetails
    Artifact      pkg.Package
}

type Vulnerability struct {
    ID       string
    Severity string
    Fix      Fix
}

type Fix struct {
    Versions []string
    State    string  // "fixed", "not-fixed", etc.
}
```

**Internal Types (minimal):**
```go
// Simple struct to track what needs updating
type PackageUpdate struct {
    Name           string  // e.g., "github.com/ulikunitz/xz"
    CurrentVersion string  // e.g., "v0.5.12"
    TargetVersion  string  // e.g., "0.5.15"
    VulnID         string  // e.g., "GHSA-jc7w-c686-c4v9"
    Severity       string  // e.g., "Medium", "High"
}

// Simple struct to track results
type UpdateResult struct {
    Update  PackageUpdate
    Success bool
    Error   error
}
```

### Error Handling Strategy

1. **Validation Errors**
   - Path doesn't exist → error message and exit
   - Path doesn't contain go.mod → error message and exit

2. **Scan Errors**
   - Grype scan fails → report error with context and exit

3. **Update Errors**
   - Individual package update fails → log error, continue with others
   - Report failed updates in summary

4. **Graceful Degradation**
   - Fix as many vulnerabilities as possible
   - Don't fail entirely if one update fails
   - Report partial success

## File Structure

```
grump/
├── cmd/
│   └── grump/
│       └── main.go              # CLI entry point
├── pkg/
│   ├── scanner/
│   │   └── scanner.go           # Grype integration
│   ├── patcher/
│   │   └── patcher.go           # gobump integration
│   └── reporter/
│       └── reporter.go          # Output formatting
├── go.mod
├── go.sum
├── Makefile
└── README.md
```

## Minimal Makefile

```makefile
.PHONY: build
build:
	go build -o bin/grump ./cmd/grump

.PHONY: clean
clean:
	rm -rf bin/

.PHONY: install
install:
	go install ./cmd/grump
```

## Success Criteria

1. **Functionality**
   - Successfully scan Go projects for vulnerabilities
   - Automatically fix all vulnerabilities that have available fixes
   - Report what was fixed

2. **Usability**
   - Simple CLI: `grump <path>`
   - Clear output showing actions taken
   - Helpful error messages

3. **Reliability**
   - Use Grype and gobump's native APIs correctly
   - Handle errors gracefully
   - Don't break go.mod

## Implementation Timeline

- **Week 1**: Phases 1-2 (Setup, Grype integration)
- **Week 2**: Phases 3-4 (gobump integration, polish)

**Total Estimated Time: 1-2 weeks for working MVP**

## Getting Started

### Step 1: Project Setup

```bash
mkdir -p grump/{cmd/grump,pkg/{scanner,patcher,reporter}}
cd grump
go mod init github.com/divolgin/grump
go get github.com/anchore/grype
go get github.com/chainguard-dev/gobump
```

### Step 2: Create Makefile

```makefile
.PHONY: build
build:
	go build -o bin/grump ./cmd/grump

.PHONY: clean  
clean:
	rm -rf bin/
```

### Step 3: Implement Grype Integration

**Research Tasks:**
1. Find Grype's main scanning function
   - Look at `github.com/anchore/grype/cmd/grype` for examples
   - Likely something like `grype.Scan()` or `grype.GetMatches()`
2. Identify the return types for scan results
3. Understand how to initialize Grype scanner

**Example starting point:**
```go
// pkg/scanner/scanner.go
package scanner

import (
    "github.com/anchore/grype/grype"
    // other grype imports
)

type Scanner struct {
    // Grype scanner configuration
}

func New() *Scanner {
    // Initialize Grype
}

func (s *Scanner) Scan(projectPath string) ([]grype.Match, error) {
    // Run Grype scan
    // Return native Grype match results
}

func (s *Scanner) GetFixableUpdates(matches []grype.Match) []PackageUpdate {
    // Filter matches where fix.state == "fixed" AND artifact.type == "go-module"
    // Extract package name and target version
    // Return list of updates needed
}
```

### Step 4: Implement gobump Integration

**Research Tasks:**
1. Find gobump's main update function
   - Look at `github.com/chainguard-dev/gobump` examples
   - Find function to bump specific dependency
2. Understand how to specify target version
3. Check if gobump handles go mod tidy

**Example starting point:**
```go
// pkg/patcher/patcher.go
package patcher

import (
    "github.com/chainguard-dev/gobump/pkg/bump"
    // other gobump imports
)

type Patcher struct {
    projectPath string
}

func New(projectPath string) *Patcher {
    return &Patcher{projectPath: projectPath}
}

func (p *Patcher) UpdatePackage(pkgName, version string) error {
    // Use gobump to update package to version
    // Return error if update fails
}

func (p *Patcher) UpdateAll(updates []PackageUpdate) []UpdateResult {
    // Update each package
    // Track results
    // Return summary
}
```

### Step 5: Connect Everything

```go
// cmd/grump/main.go
package main

import (
    "github.com/divolgin/grump/pkg/scanner"
    "github.com/divolgin/grump/pkg/patcher"
    "github.com/divolgin/grump/pkg/reporter"
)

func main() {
    // Parse args (just get directory path)
    // Initialize scanner
    // Run scan
    // Get fixable updates
    // Initialize patcher
    // Apply updates
    // Report results
}
```

## Key Implementation Notes

1. **Use Native Types**: Don't re-parse JSON. Use Grype's native Go types directly.

2. **Default Behavior**: Use Grype and gobump with their default configurations.

3. **Minimal Abstraction**: Keep the code simple. Don't over-engineer.

4. **Fix Everything**: No filtering by severity. If it has a fix, apply it.

5. **No Configuration**: Hardcode sensible defaults.

6. **Simple CLI**: Just take a path argument, nothing else needed initially.

## Example Usage Flow

```bash
# Build grump
make build

# Use grump on a project
./bin/grump /path/to/go/project

# Expected output:
# Scanning project for vulnerabilities...
# Found 3 fixable vulnerabilities:
#   - github.com/ulikunitz/xz v0.5.12 → v0.5.15 (GHSA-jc7w-c686-c4v9)
#   - github.com/hashicorp/go-getter v1.7.8 → v1.7.9 (GHSA-wjrx-6529-hcj3)
#   - github.com/go-viper/mapstructure/v2 v2.3.0 → v2.4.0 (GHSA-2464-8j7c-4cjm)
#
# Updating dependencies...
#   ✓ Updated github.com/ulikunitz/xz to v0.5.15
#   ✓ Updated github.com/hashicorp/go-getter to v1.7.9
#   ✓ Updated github.com/go-viper/mapstructure/v2 to v2.4.0
#
# Summary: Fixed 3 vulnerabilities
```

---

*This implementation plan focuses on a minimal viable product that solves the core problem.*
