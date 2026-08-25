//go:build !linux

package migration

import (
	"errors"
	"net"
)

func peerUID(_ *net.UnixConn) (uint32, error) {
	return 0, errors.New("migration broker peer credentials require Linux")
}
