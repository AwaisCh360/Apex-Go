package telemetry

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var (
	scanID  string
	agentID string
	idMu    sync.RWMutex

	defaultLogger = log.New(os.Stderr, "", log.LstdFlags)
)

func SetScanID(id string) {
	idMu.Lock()
	defer idMu.Unlock()
	scanID = id
}

func SetAgentID(id string) {
	idMu.Lock()
	defer idMu.Unlock()
	agentID = id
}

type apexLogWriter struct {
	fileWriter io.Writer
	debug      bool
}

func (w *apexLogWriter) Write(p []byte) (n int, err error) {
	idMu.RLock()
	sID := scanID
	aID := agentID
	idMu.RUnlock()

	if sID == "" {
		sID = "-"
	}
	if aID == "" {
		aID = "-"
	}

	prefix := sID + " " + aID + " "

	line := string(p)
	if !w.debug {
		// In non-debug mode, we still write to file if available
	}

	finalMsg := []byte(prefix + line)

	if w.fileWriter != nil {
		w.fileWriter.Write(finalMsg)
	}

	// Print to stdout/stderr based on debug
	// The file writer must accept all levels; the stderr writer must accept Error and above when debug=false, and Debug and above when debug=true.
	isError := strings.Contains(line, "ERROR") || strings.Contains(line, "CRITICAL") || strings.Contains(line, "FATAL")
	if w.debug || isError {
		os.Stderr.Write(finalMsg)
	}

	return len(p), nil
}

func SetupScanLogging(runDir string, debug *bool) func() {
	isDebug := false
	if debug != nil {
		isDebug = *debug
	} else {
		val := strings.ToLower(strings.TrimSpace(os.Getenv("APEX_DEBUG")))
		if val == "1" || val == "true" || val == "yes" || val == "on" {
			isDebug = true
		}
	}

	os.MkdirAll(runDir, 0755)
	logPath := filepath.Join(runDir, "apex.log")

	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("failed to open log file %s: %v\n", logPath, err)
		return func() {}
	}

	writer := &apexLogWriter{
		fileWriter: file,
		debug:      isDebug,
	}

	log.SetOutput(writer)
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	return func() {
		log.SetOutput(os.Stderr)
		log.SetFlags(log.LstdFlags)
		file.Close()
	}
}

// Ensure the old stub from telemetry.go still exists but in logging.go or keep it
// Wait, ConfigureDependencyLogging was in telemetry.go. I'll put it here.
// ConfigureDependencyLogging configures third-party dependencies to suppress non-critical logs
func ConfigureDependencyLogging() {
	// In Go, standard library packages like net/http and crypto/tls do not natively use the global logger for noisy debug logs by default.
	// However, if we were using 3rd-party libs that did (similar to Python's urllib3, asyncio), we would suppress them here to avoid spamming the console when APEX_DEBUG is false.
	// Since we use the standard library for HTTP/TLS, no explicit action is needed.
}
