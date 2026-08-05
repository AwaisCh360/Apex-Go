//go:build windows

package tui

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"os/exec"
)

func LaunchTUIProcess(ctx context.Context, command []string, env map[string]string, cwd string, stdin, stdout, stderr *os.File) (*exec.Cmd, net.Conn, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	defer listener.Close()

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, nil, err
	}
	token := hex.EncodeToString(tokenBytes)

	addr := listener.Addr().String()

	envCopy := make(map[string]string)
	for k, v := range env {
		envCopy[k] = v
	}
	envCopy["APEX_TUI_ADDR"] = addr
	envCopy["APEX_TUI_TOKEN"] = token

	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Env = envMapToList(envCopy)
	cmd.Dir = cwd
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}

	connChan := make(chan net.Conn, 1)
	errChan := make(chan error, 1)
	go func() {
		c, e := acceptAuthenticatedConnection(listener, token)
		if e != nil {
			errChan <- e
			return
		}
		connChan <- c
	}()

	select {
	case <-ctx.Done():
		TerminateProcess(cmd)
		return nil, nil, ctx.Err()
	case err := <-errChan:
		TerminateProcess(cmd)
		return nil, nil, err
	case conn := <-connChan:
		return cmd, conn, nil
	}
}
