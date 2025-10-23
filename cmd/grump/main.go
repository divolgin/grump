package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/divolgin/grump/pkg/patcher"
	"github.com/divolgin/grump/pkg/reporter"
	"github.com/divolgin/grump/pkg/scanner"
)

func main() {
	// Parse command line flags
	outputFormat := flag.String("format", "text", "Output format (text or json)")
	grypeConfig := flag.String("grype-config", "", "Path to grype config file for ignoring vulnerabilities and modules")
	flag.Parse()

	// Get the project path from arguments
	args := flag.Args()
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: grump [options] <path>\n")
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nNote: Options must come before the path argument.\n")
		fmt.Fprintf(os.Stderr, "Example: grump -format json /path/to/project\n")
		os.Exit(2)
	}

	// Validate that there's exactly one positional argument
	if len(args) > 1 {
		fmt.Fprintf(os.Stderr, "Error: too many arguments. Expected 1 path, got %d arguments: %v\n", len(args), args)
		fmt.Fprintf(os.Stderr, "\nUsage: grump [options] <path>\n")
		fmt.Fprintf(os.Stderr, "\nNote: Options must come before the path argument.\n")
		fmt.Fprintf(os.Stderr, "Example: grump -format json /path/to/project\n")
		os.Exit(2)
	}

	projectPath := args[0]

	// Validate output format
	if *outputFormat != "text" && *outputFormat != "json" {
		fmt.Fprintf(os.Stderr, "Error: invalid output format '%s'. Must be 'text' or 'json'.\n", *outputFormat)
		os.Exit(2)
	}

	// Make path absolute
	absPath, err := filepath.Abs(projectPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid path: %v\n", err)
		os.Exit(2)
	}

	// Determine the path to go.mod file
	var goModPath string
	if filepath.Base(absPath) == "go.mod" {
		// Input path already points to go.mod
		goModPath = absPath
	} else {
		// Input path is a directory, append go.mod
		goModPath = filepath.Join(absPath, "go.mod")
	}

	// Validate that go.mod exists
	if _, err := os.Stat(goModPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error: go.mod not found at %s\n", goModPath)
		os.Exit(2)
	}

	// Run the scan and fix process
	exitCode := run(goModPath, *outputFormat, *grypeConfig)
	os.Exit(exitCode)
}

func run(goModPath string, outputFormat string, grypeConfigPath string) int {
	// Initialize scanner
	fmt.Fprintln(os.Stderr, "Initializing vulnerability scanner...")
	scan, err := scanner.New(grypeConfigPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to initialize scanner: %v\n", err)
		return 2
	}
	defer scan.Close()

	// Scan the project
	fmt.Fprintf(os.Stderr, "Scanning project at %s for vulnerabilities...\n", goModPath)
	matches, _, err := scan.Scan(goModPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to scan project: %v\n", err)
		return 2
	}

	// Get fixable updates
	updates := scan.GetFixableUpdates(matches)

	if len(updates) == 0 {
		fmt.Fprintln(os.Stderr, "No fixable vulnerabilities found.")
		return 0
	}

	// Initialize patcher with the project directory
	projectDir := filepath.Dir(goModPath)
	patch, err := patcher.New(projectDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to initialize patcher: %v\n", err)
		return 2
	}

	// Apply updates
	results := patch.UpdateAll(updates)

	// Report results
	rep := reporter.New(os.Stdout)
	if err := rep.ReportResults(updates, results, outputFormat); err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to generate report: %v\n", err)
		return 2
	}

	// Determine exit code based on results
	for _, result := range results {
		if !result.Success {
			return 1 // Some vulnerabilities could not be fixed
		}
	}

	return 0 // All vulnerabilities fixed
}
