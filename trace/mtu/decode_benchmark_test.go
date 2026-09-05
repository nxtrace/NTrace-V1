package mtu

import (
	"encoding/binary"
	"net"
	"testing"
)

var (
	embeddedUDPBenchmarkPacketSink embeddedUDPPacket
	embeddedUDPBenchmarkOKSink     bool
)

func BenchmarkParseEmbeddedUDPPacket(b *testing.B) {
	tests := []struct {
		name      string
		ipVersion int
		packet    []byte
	}{
		{name: "IPv4", ipVersion: 4, packet: benchmarkEmbeddedIPv4UDP()},
		{name: "IPv6ExtensionHeader", ipVersion: 6, packet: benchmarkEmbeddedIPv6UDP()},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			if _, ok := parseEmbeddedUDPPacket(tt.packet, tt.ipVersion); !ok {
				b.Fatal("parseEmbeddedUDPPacket() ok = false")
			}
			b.SetBytes(int64(len(tt.packet)))
			b.ReportAllocs()

			for b.Loop() {
				embeddedUDPBenchmarkPacketSink, embeddedUDPBenchmarkOKSink = parseEmbeddedUDPPacket(tt.packet, tt.ipVersion)
			}
		})
	}
}

func benchmarkEmbeddedIPv4UDP() []byte {
	dstIP := net.ParseIP("203.0.113.9").To4()
	packet := make([]byte, 28)
	packet[0] = 0x45
	packet[9] = 17
	copy(packet[16:20], dstIP)
	binary.BigEndian.PutUint16(packet[20:22], 40000)
	binary.BigEndian.PutUint16(packet[22:24], 33494)
	return packet
}

func benchmarkEmbeddedIPv6UDP() []byte {
	dstIP := net.ParseIP("2001:db8::9").To16()
	packet := make([]byte, 56)
	packet[0] = 0x60
	packet[6] = 0
	copy(packet[24:40], dstIP)
	packet[40] = 17
	packet[41] = 0
	binary.BigEndian.PutUint16(packet[48:50], 40001)
	binary.BigEndian.PutUint16(packet[50:52], 33494)
	return packet
}
