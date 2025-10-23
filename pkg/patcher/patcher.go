package patcher

import (
	"fmt"
	"os"

	"github.com/chainguard-dev/gobump/pkg/types"
	"github.com/chainguard-dev/gobump/pkg/update"
	"github.com/divolgin/grump/pkg/scanner"
	"golang.org/x/mod/semver"
)

// UpdateResult represents the result of updating a package
type UpdateResult struct {
	Update  scanner.PackageUpdate
	Success bool
	Error   error
}

// Patcher handles updating Go module dependencies
type Patcher struct {
	projectPath string
}

// New creates a new Patcher instance
func New(projectPath string) (*Patcher, error) {
	return &Patcher{
		projectPath: projectPath,
	}, nil
}

// UpdatePackage updates a single package to the specified version
// Note: This does not run go tidy. Call RunGoTidy separately after updating packages.
func (p *Patcher) UpdatePackage(pkgName, version string) error {
	// Create package map for gobump
	pkgVersions := map[string]*types.Package{
		pkgName: {
			Name:    pkgName,
			Version: version,
		},
	}

	// Configure update
	config := &types.Config{
		Modroot:         p.projectPath,
		Tidy:            false,
		TidySkipInitial: true,
	}

	// Perform the update
	if _, err := update.DoUpdate(pkgVersions, config); err != nil {
		return fmt.Errorf("failed to update %s to %s: %w", pkgName, version, err)
	}

	return nil
}

// RunGoTidy runs go mod tidy on the project
func (p *Patcher) RunGoTidy() error {
	// Configure tidy-only operation
	config := &types.Config{
		Modroot:         p.projectPath,
		Tidy:            true,
		TidySkipInitial: false,
	}

	// Run tidy with empty package map
	if _, err := update.DoUpdate(map[string]*types.Package{}, config); err != nil {
		return fmt.Errorf("failed to run go mod tidy: %w", err)
	}

	return nil
}

// UpdateAll updates all packages in the list and runs go mod tidy at the end
func (p *Patcher) UpdateAll(updates []scanner.PackageUpdate) []UpdateResult {
	results := make([]UpdateResult, 0, len(updates))
	// Track which packages have been updated and to what version
	appliedVersions := make(map[string]string)

	// Update all packages first
	for _, upd := range updates {
		// Check if package has already been updated in this session
		if appliedVersion, exists := appliedVersions[upd.Name]; exists {
			// Compare versions to see if we should skip
			if shouldSkipUpdate(appliedVersion, upd.TargetVersion) {
				// Skip this update - the package is already at a newer or same version
				fmt.Fprintf(os.Stderr, "Skipping %s: already at version %s (requested %s)\n",
					upd.Name, appliedVersion, upd.TargetVersion)
				continue
			}
		}

		err := p.UpdatePackage(upd.Name, upd.TargetVersion)
		results = append(results, UpdateResult{
			Update:  upd,
			Success: err == nil,
			Error:   err,
		})

		// Track the applied version if successful
		if err == nil {
			appliedVersions[upd.Name] = upd.TargetVersion
		}
	}

	// Run go mod tidy after all updates, even if some failed
	if err := p.RunGoTidy(); err != nil {
		// Log the error but don't fail the entire operation
		fmt.Fprintf(os.Stderr, "Warning: go mod tidy failed: %v\n", err)
	}

	return results
}

// shouldSkipUpdate compares two versions and returns true if the applied version
// is the same or newer than the target version (meaning we should skip the update)
func shouldSkipUpdate(appliedVersion, targetVersion string) bool {
	// If both versions are valid semver, use semver comparison
	if semver.IsValid(appliedVersion) && semver.IsValid(targetVersion) {
		cmp := semver.Compare(appliedVersion, targetVersion)
		// Skip if applied version is greater than or equal to target
		return cmp >= 0
	}

	// For pseudo-versions or other version formats, compare as strings
	// This handles cases like v0.0.0-20250827065555 vs v0.0.0-20250224180022
	// where the applied version has a later timestamp
	return appliedVersion >= targetVersion
}
