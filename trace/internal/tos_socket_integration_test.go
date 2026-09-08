//go:build !windows

package internal

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
)

// This supplements the CLI packet-capture matrix by keeping each native socket
// alive across nonzero-to-zero transitions, including the socket TOS used to
// route UDPv4 packets whose serialized header is supplied with IP_HDRINCL.
func TestTOSSocketReuse(t *testing.T) {
	if os.Getenv("NEXTTRACE_TOS_SOCKET_INTEGRATION") != "1" {
		t.Skip("opt-in privileged native socket fixture")
	}
	for _, version := range []int{4, 6} {
		src := net.IPv4(127, 0, 0, 1)
		if version == 6 {
			src = net.IPv6loopback
		}
		for _, protocol := range []string{"icmp", "tcp", "udp"} {
			t.Run(protocol+"/"+src.String(), func(t *testing.T) {
				var send func(ipLayer) (time.Time, error)
				var read func() (int, error)
				var closeUDP func()
				switch protocol {
				case "icmp":
					s := NewICMPSpec(version, 1, 0x746f, src, src)
					if err := s.InitICMP(); err != nil {
						t.Fatal(err)
					}
					defer s.Close()
					if version == 4 {
						read = s.icmp4.TOS
						send = func(ip ipLayer) (time.Time, error) {
							return s.SendICMP(t.Context(), ip, &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(8, 0), Id: 0x746f}, nil, nil)
						}
					} else {
						read = s.icmp6.TrafficClass
						send = func(ip ipLayer) (time.Time, error) {
							return s.SendICMP(t.Context(), ip, &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(128, 0)}, &layers.ICMPv6Echo{Identifier: 0x746f}, nil)
						}
					}
				case "tcp":
					s := NewTCPSpec(version, 1, src, src, 33494, 0)
					if err := s.InitTCP(); err != nil {
						t.Fatal(err)
					}
					defer s.Close()
					if version == 4 {
						read = s.tcp4.TOS
					} else {
						read = s.tcp6.TrafficClass
					}
					send = func(ip ipLayer) (time.Time, error) {
						return s.SendTCP(t.Context(), ip, &layers.TCP{SrcPort: 47464, DstPort: 33494, SYN: true}, nil)
					}
				case "udp":
					s := NewUDPSpec(version, 1, src, src, 33494)
					if err := s.InitUDP(); err != nil {
						t.Fatal(err)
					}
					defer s.Close()
					closeUDP = s.Close
					if version == 4 {
						read = s.udp4.TOS
					} else {
						read = s.udp6.TrafficClass
					}
					send = func(ip ipLayer) (time.Time, error) {
						return s.SendUDP(t.Context(), ip, &layers.UDP{SrcPort: 47464, DstPort: 33494}, []byte{0, 1})
					}
				}
				packetProtocol := layers.IPProtocolICMPv4
				if version == 6 {
					packetProtocol = layers.IPProtocolICMPv6
				}
				switch protocol {
				case "tcp":
					packetProtocol = layers.IPProtocolTCP
				case "udp":
					packetProtocol = layers.IPProtocolUDP
				}
				var closedProbe ipLayer
				for _, tos := range []uint8{184, 255, 0} {
					var ip ipLayer = &layers.IPv4{Version: 4, TOS: tos, TTL: 1, SrcIP: src, DstIP: src, Protocol: packetProtocol}
					if version == 6 {
						ip = &layers.IPv6{Version: 6, TrafficClass: tos, HopLimit: 1, SrcIP: src, DstIP: src, NextHeader: packetProtocol}
					}
					if tos == 184 {
						closedProbe = ip
					}
					if _, err := send(ip); err != nil {
						t.Fatalf("TOS=%d: send: %v", tos, err)
					}
					got, err := read()
					if err != nil || got != int(tos) {
						t.Fatalf("TOS=%d: socket readback=%d: %v", tos, got, err)
					}
				}
				if version == 4 && protocol == "udp" {
					closeUDP()
					start, err := send(closedProbe)
					assertTOSSetupFailure(t, start, err, "IPv4 TOS")
				}
			})
		}
	}
}
