//go:build !linux || android

package internal

import (
	"errors"
	"net"
)

func setPacketConnFWMark(_ net.PacketConn, _ uint32, explicit bool) error {
	if explicit {
		return errors.New("fwmark is supported only on Linux (excluding Android)")
	}
	return nil
}
