package telemetry

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sync"
	"time"
)

var (
	SESSION_ID     string
	ConnectTimeout = 2 * time.Second
	ReadTimeout    = 3 * time.Second

	firstRunCached *bool
	firstRunMu     sync.Mutex
)

func init() {
	b := make([]byte, 8)
	rand.Read(b)
	SESSION_ID = hex.EncodeToString(b)
}

func getVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "unknown"
}

func isFirstRun() bool {
	firstRunMu.Lock()
	defer firstRunMu.Unlock()
	if firstRunCached != nil {
		return *firstRunCached
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		b := true
		firstRunCached = &b
		return true
	}

	marker := filepath.Join(homeDir, ".apex", ".seen")
	if _, err := os.Stat(marker); err == nil {
		b := false
		firstRunCached = &b
		return false
	}

	os.MkdirAll(filepath.Dir(marker), 0755)
	f, err := os.Create(marker)
	if err == nil {
		f.Close()
	}

	b := true
	firstRunCached = &b
	return true
}

func baseProps() map[string]interface{} {
	return map[string]interface{}{
		"os":           runtime.GOOS,
		"arch":         runtime.GOARCH,
		"python":       runtime.Version(), // Preserving python key semantics exactly
		"apex_version": getVersion(),
	}
}
