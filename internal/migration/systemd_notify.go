package migration

import (
	"errors"
	"net"
	"os"
	"strings"
)

func notifySystemdReady() error {
	socket := strings.TrimSpace(os.Getenv("NOTIFY_SOCKET"))
	if socket == "" {
		return nil
	}
	if !strings.HasPrefix(socket, "/") && !strings.HasPrefix(socket, "@") {
		return errors.New("systemd notify socket is invalid")
	}
	connection, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer connection.Close()
	if _, err := connection.Write([]byte("READY=1\nSTATUS=writer fences reconciled")); err != nil {
		return err
	}
	return nil
}
