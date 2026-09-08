//go:build darwin

package internal

import (
	"net"
	"testing"

	"github.com/google/gopacket/layers"
	"golang.org/x/net/ipv4"
)

func TestUDPv4TOSFailureIsInitializationError(t *testing.T) {
	conn := closedTOSSocket(t)
	s := UDPSpec{IPVersion: 4, udp: conn, udp4: ipv4.NewPacketConn(conn)}
	hdr := &layers.IPv4{Version: 4, TOS: 184, TTL: 1, SrcIP: net.IPv4(127, 0, 0, 1), DstIP: net.IPv4(127, 0, 0, 1)}
	start, err := s.SendUDP(t.Context(), hdr, &layers.UDP{}, nil)
	assertTOSSetupFailure(t, start, err, "IPv4 TOS")
}
