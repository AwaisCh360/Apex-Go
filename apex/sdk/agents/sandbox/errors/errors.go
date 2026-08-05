package errors

import "fmt"

type InvalidManifestPathError struct {
	Context map[string]interface{}
}

func (e *InvalidManifestPathError) Error() string {
	return fmt.Sprintf("invalid manifest path: %v", e.Context["rel"])
}
