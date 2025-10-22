package patcher

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/chainguard-dev/gobump/pkg/types"
	"github.com/chainguard-dev/gobump/pkg/update"
	"github.com/divolgin/grump/pkg/scanner"
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
	modFilePath := filepath.Join(projectPath, "go.mod")
	if _, err := os.Stat(modFilePath); err != nil {
		return nil, fmt.Errorf("go.mod not found at %s: %w", modFilePath, err)
	}

	return &Patcher{
		projectPath: projectPath,
	}, nil
}

// UpdatePackage updates a single package to the specified version
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
		Tidy:            true,
		TidySkipInitial: true,
	}

	// Perform the update
	if _, err := update.DoUpdate(pkgVersions, config); err != nil {
		return fmt.Errorf("failed to update %s to %s: %w", pkgName, version, err)
	}

	return nil
}

// UpdateAll updates all packages in the list
func (p *Patcher) UpdateAll(updates []scanner.PackageUpdate) []UpdateResult {
	results := make([]UpdateResult, 0, len(updates))

	for _, upd := range updates {
		err := p.UpdatePackage(upd.Name, upd.TargetVersion)
		results = append(results, UpdateResult{
			Update:  upd,
			Success: err == nil,
			Error:   err,
		})
	}

	return results
}
