//go:build linux && !android

package internal

import (
	"fmt"
	"net"
	"syscall"
)

func setPacketConnFWMark(conn net.PacketConn, mark uint32, explicit bool) error {
	if !explicit {
		return nil
	}
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return fmt.Errorf("set fwmark %#x: packet conn does not support syscall.Conn", mark)
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return fmt.Errorf("set fwmark %#x: %w", mark, err)
	}
	var optionErr error
	err = raw.Control(func(fd uintptr) {
		optionErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(mark))
	})
	if err == nil {
		err = optionErr
	}
	if err != nil {
		return fmt.Errorf("set fwmark %#x on probe socket: %w", mark, err)
	}
	return nil
}
