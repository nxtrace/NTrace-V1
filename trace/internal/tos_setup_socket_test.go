//go:build !(windows && amd64)

package internal

import (
	"net"
	"testing"

	"github.com/google/gopacket/layers"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func TestTOSSocketFailuresAreInitializationErrors(t *testing.T) {
	conn := closedTOSSocket(t)
	ip4 := &layers.IPv4{Version: 4, TOS: 184, TTL: 1, SrcIP: net.IPv4(127, 0, 0, 1), DstIP: net.IPv4(127, 0, 0, 1)}
	ip6 := &layers.IPv6{Version: 6, TrafficClass: 184, HopLimit: 1, SrcIP: net.IPv6loopback, DstIP: net.IPv6loopback}
	t.Run("icmp6", func(t *testing.T) {
		s := ICMPSpec{IPVersion: 6, icmp: conn, icmp6: ipv6.NewPacketConn(conn)}
		start, err := s.SendICMP(t.Context(), ip6, &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(128, 0)}, &layers.ICMPv6Echo{}, nil)
		assertTOSSetupFailure(t, start, err, "IPv6 Traffic Class")
	})
	t.Run("tcp4", func(t *testing.T) {
		s := TCPSpec{IPVersion: 4, tcp: conn, tcp4: ipv4.NewPacketConn(conn)}
		start, err := s.SendTCP(t.Context(), ip4, &layers.TCP{}, nil)
		assertTOSSetupFailure(t, start, err, "IPv4 TOS")
	})
	t.Run("tcp6", func(t *testing.T) {
		s := TCPSpec{IPVersion: 6, tcp: conn, tcp6: ipv6.NewPacketConn(conn)}
		start, err := s.SendTCP(t.Context(), ip6, &layers.TCP{}, nil)
		assertTOSSetupFailure(t, start, err, "IPv6 Traffic Class")
	})
	t.Run("udp6", func(t *testing.T) {
		s := UDPSpec{IPVersion: 6, udp: conn, udp6: ipv6.NewPacketConn(conn)}
		start, err := s.SendUDP(t.Context(), ip6, &layers.UDP{}, nil)
		assertTOSSetupFailure(t, start, err, "IPv6 Traffic Class")
	})
}
