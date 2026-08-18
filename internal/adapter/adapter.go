package adapter

import (
	"context"

	"kyrecovery-server/internal/capsule"
)

// CheckItem represents a discrete verification step during a restore drill.
type CheckItem struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Message string `json:"message"`
}

// DrillResult contains the structured outcome of a service restore verification drill.
type DrillResult struct {
	Passed              bool                   `json:"passed"`
	Checks              []CheckItem            `json:"checks"`
	MissingDependencies []string               `json:"missing_dependencies"`
	ErrorMessage        string                 `json:"error_message,omitempty"`
	Details             map[string]interface{} `json:"details,omitempty"`
}

// ServiceAdapter defines the interface for service-specific capture and restore verification.
type ServiceAdapter interface {
	Name() string
	Capture(ctx context.Context, sourceDir string) (map[string][]byte, []capsule.Dependency, error)
	VerifyRestore(ctx context.Context, extractedDir string, manifest *capsule.Manifest) (*DrillResult, error)
}
