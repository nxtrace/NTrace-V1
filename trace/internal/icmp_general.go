//go:build !darwin

package internal

import "net"

func ListenPacket(network string, address string) (net.PacketConn, error) {
	return net.ListenPacket(network, address)
}
