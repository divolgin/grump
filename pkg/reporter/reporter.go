package reporter

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/divolgin/grump/pkg/patcher"
	"github.com/divolgin/grump/pkg/scanner"
)

// Report contains the summary of the scan and fix operation
type Report struct {
	TotalVulnerabilities  int            `json:"total_vulnerabilities"`
	VulnerabilitiesFixed  int            `json:"vulnerabilities_fixed"`
	VulnerabilitiesFailed int            `json:"vulnerabilities_failed"`
	PackagesUpdated       int            `json:"packages_updated"`
	PackagesFailed        int            `json:"packages_failed"`
	Updates               []UpdateReport `json:"updates"`
}

// ResultStats contains statistics about the update results
type ResultStats struct {
	PackagesUpdated       int
	PackagesFailed        int
	VulnerabilitiesFixed  int
	VulnerabilitiesFailed int
}

// AnalyzeResults analyzes update results and returns statistics
func AnalyzeResults(updates []scanner.PackageUpdate, results []patcher.UpdateResult) ResultStats {
	stats := ResultStats{}

	// Build a map of successfully updated packages
	updatedPackages := make(map[string]bool)
	for _, result := range results {
		if result.Success {
			stats.PackagesUpdated++
			updatedPackages[result.Update.Name] = true
		} else {
			stats.PackagesFailed++
		}
	}

	// Count how many vulnerabilities are fixed by these package updates
	for _, update := range updates {
		if updatedPackages[update.Name] {
			stats.VulnerabilitiesFixed++
		} else {
			// Check if this package had any failed updates
			hasFailed := false
			for _, result := range results {
				if result.Update.Name == update.Name && !result.Success {
					hasFailed = true
					break
				}
			}
			if hasFailed {
				stats.VulnerabilitiesFailed++
			}
		}
	}

	return stats
}

// UpdateReport contains details about a single update
type UpdateReport struct {
	Package        string `json:"package"`
	CurrentVersion string `json:"current_version"`
	TargetVersion  string `json:"target_version"`
	VulnID         string `json:"vulnerability_id"`
	Severity       string `json:"severity"`
	Success        bool   `json:"success"`
	Error          string `json:"error,omitempty"`
}

// Reporter handles output formatting
type Reporter struct {
	writer io.Writer
}

// New creates a new Reporter instance
func New(writer io.Writer) *Reporter {
	return &Reporter{writer: writer}
}

// ReportResults outputs the results of the scan and update operation
func (r *Reporter) ReportResults(updates []scanner.PackageUpdate, results []patcher.UpdateResult, format string) error {
	if format == "json" {
		return r.reportJSON(updates, results)
	}
	return r.reportText(updates, results)
}

// reportText outputs results in human-readable text format
func (r *Reporter) reportText(updates []scanner.PackageUpdate, results []patcher.UpdateResult) error {
	if len(updates) == 0 {
		fmt.Fprintln(r.writer, "No fixable vulnerabilities found.")
		return nil
	}

	fmt.Fprintf(r.writer, "Found %d fixable vulnerabilities:\n", len(updates))
	for _, update := range updates {
		fmt.Fprintf(r.writer, "  - %s %s → %s (%s, %s)\n",
			update.Name,
			update.CurrentVersion,
			update.TargetVersion,
			update.VulnID,
			update.Severity,
		)
	}

	fmt.Fprintln(r.writer, "\nUpdating dependencies...")

	for _, result := range results {
		if result.Success {
			fmt.Fprintf(r.writer, "  ✓ Updated %s to %s\n",
				result.Update.Name,
				result.Update.TargetVersion,
			)
		} else {
			fmt.Fprintf(r.writer, "  ✗ Failed to update %s: %v\n",
				result.Update.Name,
				result.Error,
			)
		}
	}

	// Analyze results to get statistics
	stats := AnalyzeResults(updates, results)

	fmt.Fprintf(r.writer, "\nSummary: Updated %d package(s) to fix %d vulnerabilities", stats.PackagesUpdated, stats.VulnerabilitiesFixed)
	if stats.PackagesFailed > 0 {
		fmt.Fprintf(r.writer, ", %d package(s) failed (%d vulnerabilities not fixed)", stats.PackagesFailed, stats.VulnerabilitiesFailed)
	}
	fmt.Fprintln(r.writer)

	return nil
}

// reportJSON outputs results in JSON format
func (r *Reporter) reportJSON(updates []scanner.PackageUpdate, results []patcher.UpdateResult) error {
	// Analyze results to get statistics
	stats := AnalyzeResults(updates, results)

	report := Report{
		TotalVulnerabilities:  len(updates),
		VulnerabilitiesFixed:  stats.VulnerabilitiesFixed,
		VulnerabilitiesFailed: stats.VulnerabilitiesFailed,
		PackagesUpdated:       stats.PackagesUpdated,
		PackagesFailed:        stats.PackagesFailed,
		Updates:               make([]UpdateReport, 0, len(results)),
	}

	for _, result := range results {
		updateReport := UpdateReport{
			Package:        result.Update.Name,
			CurrentVersion: result.Update.CurrentVersion,
			TargetVersion:  result.Update.TargetVersion,
			VulnID:         result.Update.VulnID,
			Severity:       result.Update.Severity,
			Success:        result.Success,
		}

		if result.Error != nil {
			updateReport.Error = result.Error.Error()
		}

		report.Updates = append(report.Updates, updateReport)
	}

	encoder := json.NewEncoder(r.writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
