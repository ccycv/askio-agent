//go:build linux

package migration

import (
	"fmt"
	"net"
	"syscall"
)

func peerUID(connection *net.UnixConn) (uint32, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err != nil {
			socketErr = err
			return
		}
		uid = credentials.Uid
	}); err != nil {
		return 0, err
	}
	if socketErr != nil {
		return 0, fmt.Errorf("read broker peer credentials: %w", socketErr)
	}
	return uid, nil
}
