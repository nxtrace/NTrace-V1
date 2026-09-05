package mtu

import (
	"encoding/binary"
	"testing"
)

const fuzzEmbeddedUDPMaxBytes = 4096

func FuzzParseEmbeddedUDPPacket(f *testing.F) {
	f.Add(uint8(4), fuzzEmbeddedUDPSeed(4))
	f.Add(uint8(6), fuzzEmbeddedUDPSeed(6))
	f.Add(uint8(6), []byte{0x60, 0, 0, 0})

	f.Fuzz(func(t *testing.T, version uint8, data []byte) {
		if len(data) > fuzzEmbeddedUDPMaxBytes {
			data = data[:fuzzEmbeddedUDPMaxBytes]
		}
		ipVersion := 4
		if version == 6 || version%2 == 1 {
			ipVersion = 6
		}
		packet, ok := parseEmbeddedUDPPacket(data, ipVersion)
		if !ok {
			return
		}
		if packet.dstIP == nil || packet.dstIP.To16() == nil {
			t.Fatalf("parsed destination IP = %v", packet.dstIP)
		}
		if ipVersion == 4 && packet.dstIP.To4() == nil {
			t.Fatalf("IPv4 parser returned destination %v", packet.dstIP)
		}
		if ipVersion == 6 && packet.dstIP.To4() != nil {
			t.Fatalf("IPv6 parser returned destination %v", packet.dstIP)
		}
		if packet.srcPort < 0 || packet.srcPort > 65535 || packet.dstPort < 0 || packet.dstPort > 65535 {
			t.Fatalf("ports outside 0..65535: source=%d destination=%d", packet.srcPort, packet.dstPort)
		}

		encoded := encodeFuzzEmbeddedUDP(ipVersion, packet)
		roundTrip, valid := parseEmbeddedUDPPacket(encoded, ipVersion)
		if !valid || !roundTrip.dstIP.Equal(packet.dstIP) || roundTrip.srcPort != packet.srcPort || roundTrip.dstPort != packet.dstPort {
			t.Fatalf("embedded UDP round-trip = (%+v, %v), want %+v", roundTrip, valid, packet)
		}
	})
}

func fuzzEmbeddedUDPSeed(ipVersion int) []byte {
	packet := embeddedUDPPacket{srcPort: 40000, dstPort: 33494}
	if ipVersion == 4 {
		packet.dstIP = []byte{192, 0, 2, 9}
	} else {
		packet.dstIP = []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9}
	}
	return encodeFuzzEmbeddedUDP(ipVersion, packet)
}

func encodeFuzzEmbeddedUDP(ipVersion int, packet embeddedUDPPacket) []byte {
	if ipVersion == 4 {
		encoded := make([]byte, 28)
		encoded[0] = 0x45
		encoded[9] = 17
		copy(encoded[16:20], packet.dstIP.To4())
		binary.BigEndian.PutUint16(encoded[20:22], uint16(packet.srcPort))
		binary.BigEndian.PutUint16(encoded[22:24], uint16(packet.dstPort))
		return encoded
	}

	encoded := make([]byte, 48)
	encoded[0] = 0x60
	encoded[6] = 17
	copy(encoded[24:40], packet.dstIP.To16())
	binary.BigEndian.PutUint16(encoded[40:42], uint16(packet.srcPort))
	binary.BigEndian.PutUint16(encoded[42:44], uint16(packet.dstPort))
	return encoded
}
