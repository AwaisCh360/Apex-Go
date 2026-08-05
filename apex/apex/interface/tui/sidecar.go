package tui

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"
)

const (
	WindowsAuthTimeout = 10 * time.Second
	ProcessExitTimeout = 5 * time.Second
)

var (
	SensitiveEnvSuffixes = []string{"_API_KEY", "_ACCESS_KEY"}
	SensitiveEnvParts    = map[string]bool{
		"CREDENTIAL":  true,
		"CREDENTIALS": true,
		"PASSWORD":    true,
		"SECRET":      true,
		"SECRETS":     true,
		"TOKEN":       true,
		"TOKENS":      true,
	}
	SensitiveEnvNames = map[string]bool{
		"AWS_ACCESS_KEY_ID":              true,
		"GOOGLE_APPLICATION_CREDENTIALS": true,
		"LLM_API_KEY":                    true,
		"APEX_TUI_ADDR":                  true,
		"APEX_TUI_FD":                    true,
		"APEX_TUI_TOKEN":                 true,
	}
)

func TUIExecutable() string {
	if runtime.GOOS == "windows" {
		return "apex-tui.exe"
	}
	return "apex-tui"
}

func ProjectRoot() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return ""
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}

func TUISourceDir() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return ""
	}
	return filepath.Dir(file)
}

func ChildEnvironment() map[string]string {
	child := make(map[string]string)
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, value := parts[0], parts[1]
		normalized := strings.ToUpper(key)

		if SensitiveEnvNames[normalized] {
			continue
		}

		hasSuffix := false
		for _, suffix := range SensitiveEnvSuffixes {
			if strings.HasSuffix(normalized, suffix) {
				hasSuffix = true
				break
			}
		}
		if hasSuffix {
			continue
		}

		hasPart := false
		for _, part := range strings.Split(normalized, "_") {
			if SensitiveEnvParts[part] {
				hasPart = true
				break
			}
		}
		if hasPart {
			continue
		}

		child[key] = value
	}
	return child
}

func envMapToList(m map[string]string) []string {
	var l []string
	for k, v := range m {
		l = append(l, fmt.Sprintf("%s=%s", k, v))
	}
	return l
}

func recvExactly(conn net.Conn, size int) ([]byte, error) {
	buf := make([]byte, size)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return nil, fmt.Errorf("TUI IPC peer closed during authentication: %w", err)
	}
	return buf, nil
}

func authenticateConnection(conn net.Conn, expectedToken string) error {
	addr := conn.RemoteAddr().String()
	host, _, err := net.SplitHostPort(addr)
	if err != nil || (host != "127.0.0.1" && host != "::1") {
		return errors.New("TUI IPC connection did not originate from loopback")
	}

	conn.SetDeadline(time.Now().Add(WindowsAuthTimeout))
	suppliedBytes, err := recvExactly(conn, len(expectedToken))
	if err != nil {
		return err
	}

	supplied := string(suppliedBytes)
	if subtle.ConstantTimeCompare([]byte(supplied), []byte(expectedToken)) != 1 {
		return errors.New("TUI IPC authentication failed")
	}
	conn.SetDeadline(time.Time{})
	return nil
}

func acceptAuthenticatedConnection(listener net.Listener, expectedToken string) (net.Conn, error) {
	if tcpListener, ok := listener.(*net.TCPListener); ok {
		tcpListener.SetDeadline(time.Now().Add(WindowsAuthTimeout))
	}
	conn, err := listener.Accept()
	if err != nil {
		return nil, err
	}
	if tcpListener, ok := listener.(*net.TCPListener); ok {
		tcpListener.SetDeadline(time.Time{})
	}

	if err := authenticateConnection(conn, expectedToken); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func WaitProcess(ctx context.Context, cmd *exec.Cmd) int {
	err := cmd.Wait()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode()
		}
		return -1
	}
	return 0
}

func TerminateProcess(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}

	if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
		return nil
	}

	// Attempt graceful termination. Suppress expected errors (e.g. already exited / ProcessLookupError)
	_ = cmd.Process.Signal(os.Interrupt)

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-done:
		// Exited gracefully within the first timeout
		return nil
	case <-time.After(ProcessExitTimeout):
		// Timeout reached, force kill
		_ = cmd.Process.Kill()

		// Wait again to ensure complete process cleanup
		select {
		case <-done:
		case <-time.After(ProcessExitTimeout):
			// Process still hung after kill and timeout, but we must return
		}
	}
	return nil
}

func CheckReturnCode(returnCode int) error {
	if returnCode != 0 {
		return fmt.Errorf("Bubble Tea TUI exited with status %d", returnCode)
	}
	return nil
}

func PackageVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path == "github.com/useapex/apex-agent" {
				return dep.Version
			}
		}
	}
	return "dev"
}
