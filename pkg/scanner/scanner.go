package scanner

import (
	"context"
	"fmt"
	"strings"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

// PackageUpdate represents a package that needs to be updated
type PackageUpdate struct {
	Name           string // e.g., "github.com/ulikunitz/xz"
	CurrentVersion string // e.g., "v0.5.12"
	TargetVersion  string // e.g., "0.5.15"
	VulnID         string // e.g., "GHSA-jc7w-c686-c4v9"
	Severity       string // e.g., "Medium", "High"
}

// Scanner wraps Grype functionality
type Scanner struct {
	store vulnerability.Provider
}

// New creates a new Scanner instance
func New() (*Scanner, error) {
	// Create a minimal clio.Identification
	id := clio.Identification{
		Name:    "grump",
		Version: "dev",
	}

	// Load the vulnerability database with default configs
	distCfg := distribution.DefaultConfig()
	installCfg := installation.DefaultConfig(id)

	dbStore, _, err := grype.LoadVulnerabilityDB(distCfg, installCfg, true)
	if err != nil {
		return nil, fmt.Errorf("failed to load vulnerability database: %w", err)
	}

	return &Scanner{
		store: dbStore,
	}, nil
}

// Scan scans a project directory for vulnerabilities
func (s *Scanner) Scan(projectPath string) (match.Matches, []pkg.Package, error) {
	ctx := context.Background()

	// Create a source from the directory
	src, err := syft.GetSource(ctx, projectPath, syft.DefaultGetSourceConfig())
	if err != nil {
		return match.NewMatches(), nil, fmt.Errorf("failed to create source: %w", err)
	}
	defer src.Close()

	// Create SBOM from source with default configuration
	sbomResult, err := syft.CreateSBOM(ctx, src, nil)
	if err != nil {
		return match.NewMatches(), nil, fmt.Errorf("failed to create SBOM: %w", err)
	}

	// Convert Syft packages to Grype packages
	grypePackages := pkg.FromCollection(sbomResult.Artifacts.Packages, pkg.SynthesisConfig{})

	// Create package context
	pkgContext := pkg.Context{
		Source: &sbomResult.Source,
		Distro: nil, // Will be populated from SBOM if needed
	}

	// Create matchers
	matchers := matcher.NewDefaultMatchers(matcher.Config{})

	// Find vulnerabilities using VulnerabilityMatcher
	runner := grype.VulnerabilityMatcher{
		VulnerabilityProvider: s.store,
		Matchers:              matchers,
		NormalizeByCVE:        false,
	}

	results, _, err := runner.FindMatches(grypePackages, pkgContext)
	if err != nil {
		return match.NewMatches(), nil, fmt.Errorf("failed to find vulnerabilities: %w", err)
	}

	if results == nil {
		return match.NewMatches(), grypePackages, nil
	}

	return *results, grypePackages, nil
}

// normalizeVersion normalizes a version by copying the prefix from the current version
// if the target version is missing it
func normalizeVersion(currentVersion, targetVersion string) string {
	// Parse the current version as semver
	if !semver.IsValid(currentVersion) {
		// If current version is not valid semver, return target as-is
		return targetVersion
	}

	// Extract major.minor.patch from parsed semver
	majorMinorPatch := semver.Canonical(currentVersion)
	// Remove the 'v' prefix that Canonical adds
	if strings.HasPrefix(majorMinorPatch, "v") {
		majorMinorPatch = majorMinorPatch[1:]
	}

	// Find the major.minor.patch substring in currentVersion
	idx := strings.Index(currentVersion, majorMinorPatch)
	if idx == -1 {
		// If we can't find it, return target as-is
		return targetVersion
	}

	// Extract the prefix (everything to the left of major.minor.patch)
	prefix := currentVersion[:idx]

	// Apply the prefix to the target version
	return prefix + targetVersion
}

// isValidGoVersion checks if a version string is valid for a Go module
func isValidGoVersion(pkgName, version string) bool {
	// Check if it's a valid semantic version
	if semver.IsValid(version) {
		return true
	}

	// Try to validate as a module version using module.Check
	// This will validate both semver and pseudo-versions
	err := module.Check(pkgName, version)
	return err == nil
}

// GetFixableUpdates extracts fixable Go module updates from scan results
func (s *Scanner) GetFixableUpdates(matches match.Matches) []PackageUpdate {
	var updates []PackageUpdate

	for m := range matches.Enumerate() {
		// Filter: only Go modules with fixes
		if m.Package.Type != syftPkg.GoModulePkg {
			continue
		}

		// Check if vulnerability has a fix
		if len(m.Vulnerability.Fix.Versions) == 0 || m.Vulnerability.Fix.State != vulnerability.FixStateFixed {
			continue
		}

		// Extract the suggested version
		suggestedVersion := ""
		if len(m.Vulnerability.Fix.Versions) > 0 {
			suggestedVersion = m.Vulnerability.Fix.Versions[0]
		}

		if suggestedVersion == "" {
			continue
		}

		// Normalize the version by copying prefix from current version
		normalizedVersion := normalizeVersion(m.Package.Version, suggestedVersion)

		// Validate the version is parseable
		if !isValidGoVersion(m.Package.Name, normalizedVersion) {
			fmt.Printf("Requesting pin to %s.\n This is not a valid SemVer, so skipping version check.\n", normalizedVersion)
			continue
		}

		// Extract severity from metadata
		severity := "Unknown"
		if m.Vulnerability.Metadata != nil {
			severity = m.Vulnerability.Metadata.Severity
		}

		updates = append(updates, PackageUpdate{
			Name:           m.Package.Name,
			CurrentVersion: m.Package.Version,
			TargetVersion:  normalizedVersion,
			VulnID:         m.Vulnerability.ID,
			Severity:       severity,
		})
	}

	return updates
}

// Close cleans up resources
func (s *Scanner) Close() {
	// Note: vulnerability.Provider interface doesn't have a Close method
	// Resources are automatically cleaned up
}
