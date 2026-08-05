package errors

type InvalidManifestPathError struct {
	Context map[string]interface{}
}

func (e *InvalidManifestPathError) Error() string { return "" }
