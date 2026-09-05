package internal

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const fuzzPacketMaxBytes = 4096

func FuzzParseSocketICMPMessage(f *testing.F) {
	f.Add(uint8(4), fuzzICMPTimeExceededSeed(f, 4))
	f.Add(uint8(6), fuzzICMPTimeExceededSeed(f, 6))
	f.Add(uint8(4), []byte{0, 0, 0, 0})

	f.Fuzz(func(t *testing.T, version uint8, raw []byte) {
		raw = capFuzzPacket(raw)
		ipVersion := fuzzIPVersion(version)
		message, ok := parseSocketICMPMessage(ipVersion, raw)
		if !ok {
			if message != nil {
				t.Fatal("failed ICMP parse returned a message")
			}
			return
		}
		if message == nil {
			t.Fatal("successful ICMP parse returned nil")
		}
		response := classifySocketICMPResponse(ipVersion, message, raw)
		if response.Kind > ICMPResponseUnreachable {
			t.Fatalf("response kind = %d, outside known range", response.Kind)
		}

		encoded, err := message.Marshal(nil)
		if err != nil {
			return
		}
		if roundTrip, valid := parseSocketICMPMessage(ipVersion, encoded); !valid || roundTrip == nil {
			t.Fatal("marshaled ICMP message did not parse")
		}
	})
}

func FuzzExtractEmbeddedICMPSeq(f *testing.F) {
	f.Add(uint16(13), buildIPv4InnerPacket(net.ParseIP("192.0.2.9"), 13, 99))
	f.Add(uint16(17), buildIPv6InnerPacket(net.ParseIP("2001:db8::9"), 17, 123))
	f.Add(uint16(1), []byte{0x45})

	f.Fuzz(func(t *testing.T, echoID uint16, data []byte) {
		data = capFuzzPacket(data)
		seq, ok := extractEmbeddedICMPSeq(data, int(echoID))
		if !ok {
			return
		}
		if seq < 0 || seq > 65535 {
			t.Fatalf("embedded ICMP sequence = %d, outside 0..65535", seq)
		}

		var encoded []byte
		switch {
		case len(data) >= 20 && data[0]>>4 == 4:
			encoded = buildIPv4InnerPacket(net.IP(data[16:20]), int(echoID), seq)
		case len(data) >= 40 && data[0]>>4 == 6:
			encoded = buildIPv6InnerPacket(net.IP(data[24:40]), int(echoID), seq)
		default:
			return
		}
		if roundTrip, valid := extractEmbeddedICMPSeq(encoded, int(echoID)); !valid || roundTrip != seq {
			t.Fatalf("embedded ICMP round-trip = (%d, %v), want (%d, true)", roundTrip, valid, seq)
		}
	})
}

func FuzzDecodeTCPProbePacket(f *testing.F) {
	f.Add(uint8(4), uint16(443), fuzzIPv4TCPSeed())
	f.Add(uint8(6), uint16(8443), fuzzIPv6TCPSeed())
	f.Add(uint8(4), uint16(80), []byte{0x45})

	f.Fuzz(func(t *testing.T, version uint8, dstPort uint16, raw []byte) {
		raw = capFuzzPacket(raw)
		ipVersion := fuzzIPVersion(version)
		layerType := layers.LayerTypeIPv4
		if ipVersion == 6 {
			layerType = layers.LayerTypeIPv6
		}
		packet := gopacket.NewPacket(raw, layerType, gopacket.NoCopy)
		srcPort, seq, ack, peer, ok := decodeTCPProbePacket(ipVersion, int(dstPort), packet)
		if !ok {
			return
		}
		if srcPort < 0 || srcPort > 65535 {
			t.Fatalf("source port = %d, outside 0..65535", srcPort)
		}
		if seq != 0 && ack != 0 {
			t.Fatalf("decoder returned both sequence %d and ack %d", seq, ack)
		}
		peerIP, valid := peer.(*net.IPAddr)
		if !valid || peerIP == nil || peerIP.IP == nil {
			t.Fatalf("peer = %#v, want non-nil IP address", peer)
		}
		if ipVersion == 4 && peerIP.IP.To4() == nil {
			t.Fatalf("IPv4 decoder returned peer %v", peerIP.IP)
		}
		if ipVersion == 6 && (peerIP.IP.To16() == nil || peerIP.IP.To4() != nil) {
			t.Fatalf("IPv6 decoder returned peer %v", peerIP.IP)
		}
	})
}

func capFuzzPacket(raw []byte) []byte {
	if len(raw) > fuzzPacketMaxBytes {
		return raw[:fuzzPacketMaxBytes]
	}
	return raw
}

func fuzzIPVersion(version uint8) int {
	if version == 6 || version%2 == 1 {
		return 6
	}
	return 4
}

func fuzzICMPTimeExceededSeed(f *testing.F, ipVersion int) []byte {
	inner := make([]byte, 48)
	inner[0] = 0x60
	messageType := icmp.Type(ipv6.ICMPTypeTimeExceeded)
	if ipVersion == 4 {
		inner = make([]byte, 28)
		inner[0] = 0x45
		messageType = ipv4.ICMPTypeTimeExceeded
	}
	raw, err := (&icmp.Message{Type: messageType, Body: &icmp.TimeExceeded{Data: inner}}).Marshal(nil)
	if err != nil {
		f.Fatalf("marshal ICMP seed: %v", err)
	}
	return raw
}

func fuzzIPv4TCPSeed() []byte {
	return []byte{
		0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00,
		0xc6, 0x33, 0x64, 0x01, 0xc0, 0x00, 0x02, 0x09,
		0x01, 0xbb, 0x7d, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc8,
		0x50, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
}

func fuzzIPv6TCPSeed() []byte {
	return []byte{
		0x60, 0x00, 0x00, 0x00, 0x00, 0x14, 0x06, 0x40,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09,
		0x20, 0xfb, 0xb2, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5b,
		0x50, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
}
