//go:build !windows

package tui

import (
	"context"
	"net"
	"os"
	"os/exec"

	"golang.org/x/sys/unix"
)

func LaunchTUIProcess(ctx context.Context, command []string, env map[string]string, cwd string) (*exec.Cmd, net.Conn, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, nil, err
	}

	backendFile := os.NewFile(uintptr(fds[0]), "backend")
	childFile := os.NewFile(uintptr(fds[1]), "child")
	defer childFile.Close()

	backendConn, err := net.FileConn(backendFile)
	backendFile.Close() // FileConn duped the fd, so we close original
	if err != nil {
		return nil, nil, err
	}

	envCopy := make(map[string]string)
	for k, v := range env {
		envCopy[k] = v
	}
	envCopy["APEX_TUI_FD"] = "3"

	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Env = envMapToList(envCopy)
	cmd.Dir = cwd
	cmd.ExtraFiles = []*os.File{childFile}

	if err := cmd.Start(); err != nil {
		backendConn.Close()
		return nil, nil, err
	}

	return cmd, backendConn, nil
}
