package core

import (
	"os"
	"path/filepath"
)

const (
	RunsDirName         = "apex_runs"
	RuntimeStateDirName = ".state"
	RunRecordFilename   = "run.json"
)

func RunDirFor(runName string, cwd string) string {
	base := cwd
	if base == "" {
		base, _ = os.Getwd()
	}
	return filepath.Join(base, RunsDirName, runName)
}

func RuntimeStateDir(runDir string) string {
	return filepath.Join(runDir, RuntimeStateDirName)
}

func RunRecordPath(runDir string) string {
	return filepath.Join(runDir, RunRecordFilename)
}

func RunsBaseDir(cwd string) string {
	base := cwd
	if base == "" {
		base, _ = os.Getwd()
	}
	return filepath.Join(base, RunsDirName)
}

func LatestRunDir(cwd string) string {
	base := RunsBaseDir(cwd)
	stat, err := os.Stat(base)
	if err != nil || !stat.IsDir() {
		return ""
	}

	entries, err := os.ReadDir(base)
	if err != nil {
		return ""
	}

	var candidates []string
	for _, entry := range entries {
		child := filepath.Join(base, entry.Name())
		recordPath := RunRecordPath(child)
		if stat, err := os.Stat(recordPath); err == nil && !stat.IsDir() {
			candidates = append(candidates, child)
		}
	}

	if len(candidates) == 0 {
		return ""
	}

	var latest string
	var maxTime int64
	for _, child := range candidates {
		recordPath := RunRecordPath(child)
		if stat, err := os.Stat(recordPath); err == nil {
			mtime := stat.ModTime().UnixNano()
			if latest == "" || mtime > maxTime {
				maxTime = mtime
				latest = child
			}
		}
	}
	return latest
}
