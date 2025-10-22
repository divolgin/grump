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
	flag.Parse()

	// Get the project path from arguments
	args := flag.Args()
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: grump [options] <path>\n")
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		flag.PrintDefaults()
		os.Exit(2)
	}

	projectPath := args[0]

	// Make path absolute
	absPath, err := filepath.Abs(projectPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid path: %v\n", err)
		os.Exit(2)
	}

	// Validate that go.mod exists
	modFilePath := filepath.Join(absPath, "go.mod")
	if _, err := os.Stat(modFilePath); err != nil {
		fmt.Fprintf(os.Stderr, "Error: go.mod not found at %s\n", modFilePath)
		os.Exit(2)
	}

	// Run the scan and fix process
	exitCode := run(absPath, *outputFormat)
	os.Exit(exitCode)
}

func run(projectPath string, outputFormat string) int {
	// Initialize scanner
	fmt.Fprintln(os.Stderr, "Initializing vulnerability scanner...")
	scan, err := scanner.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to initialize scanner: %v\n", err)
		return 2
	}
	defer scan.Close()

	// Scan the project
	fmt.Fprintf(os.Stderr, "Scanning project at %s for vulnerabilities...\n", projectPath)
	matches, _, err := scan.Scan(projectPath)
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

	// Initialize patcher
	patch, err := patcher.New(projectPath)
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
