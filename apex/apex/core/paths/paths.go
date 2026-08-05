package paths

import "path/filepath"

// RunRecordPath is a placeholder for apex.core.paths.run_record_path.
func RunRecordPath(runDir string) string {
	return filepath.Join(runDir, "run.json")
}
