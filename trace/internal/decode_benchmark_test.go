package internal

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var (
	decodeBenchmarkFinishSink   time.Time
	decodeBenchmarkSrcPortSink  int
	decodeBenchmarkSeqSink      int
	decodeBenchmarkAckSink      int
	decodeBenchmarkDataSink     []byte
	decodeBenchmarkResponseSink ICMPResponse
	decodeBenchmarkPeerSink     net.Addr
	decodeBenchmarkOKSink       bool
)

func BenchmarkDecodeICMPSocketMessage(b *testing.B) {
	tests := []struct {
		name      string
		ipVersion int
		dstIP     net.IP
		peerIP    net.IP
		echoID    int
		seq       int
	}{
		{
			name:      "IPv4TimeExceeded",
			ipVersion: 4,
			dstIP:     net.ParseIP("192.0.2.9"),
			peerIP:    net.ParseIP("198.51.100.1"),
			echoID:    401,
			seq:       1234,
		},
		{
			name:      "IPv6TimeExceeded",
			ipVersion: 6,
			dstIP:     net.ParseIP("2001:db8::9"),
			peerIP:    net.ParseIP("2001:db8::1"),
			echoID:    402,
			seq:       2345,
		},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			inner := benchmarkEmbeddedICMPPacket(tt.ipVersion, tt.dstIP, tt.echoID, tt.seq)
			raw := benchmarkICMPTimeExceeded(b, tt.ipVersion, inner)
			spec := &ICMPSpec{IPVersion: tt.ipVersion, EchoID: tt.echoID, DstIP: tt.dstIP}
			msg := ReceivedMessage{Peer: &net.IPAddr{IP: tt.peerIP}, Msg: raw}
			if _, seq, response, ok := spec.decodeICMPSocketMessage(msg); !ok || seq != tt.seq || response.Kind != ICMPResponseTransit {
				b.Fatalf("decodeICMPSocketMessage() = (_, %d, %#v, %v), want (_, %d, Transit, true)", seq, response, ok, tt.seq)
			}
			b.SetBytes(int64(len(raw)))
			b.ReportAllocs()

			for b.Loop() {
				decodeBenchmarkFinishSink, decodeBenchmarkSeqSink, decodeBenchmarkResponseSink, decodeBenchmarkOKSink = spec.decodeICMPSocketMessage(msg)
			}
		})
	}
}

func BenchmarkDecodeTCPProbePacket(b *testing.B) {
	tests := []struct {
		name      string
		ipVersion int
		dstPort   int
		packet    func(*testing.B) gopacket.Packet
	}{
		{
			name:      "IPv4RSTAck",
			ipVersion: 4,
			dstPort:   443,
			packet: func(b *testing.B) gopacket.Packet {
				return benchmarkSerializeTCPPacket(b, &layers.IPv4{
					Version:  4,
					IHL:      5,
					Protocol: layers.IPProtocolTCP,
					SrcIP:    net.ParseIP("198.51.100.1").To4(),
					DstIP:    net.ParseIP("192.0.2.9").To4(),
				}, &layers.TCP{SrcPort: 443, DstPort: 32100, ACK: true, RST: true, Ack: 200})
			},
		},
		{
			name:      "IPv6SYNAck",
			ipVersion: 6,
			dstPort:   8443,
			packet: func(b *testing.B) gopacket.Packet {
				return benchmarkSerializeTCPPacket(b, &layers.IPv6{
					Version:    6,
					NextHeader: layers.IPProtocolTCP,
					SrcIP:      net.ParseIP("2001:db8::1"),
					DstIP:      net.ParseIP("2001:db8::9"),
				}, &layers.TCP{SrcPort: 8443, DstPort: 45678, ACK: true, SYN: true, Ack: 91})
			},
		},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			packet := tt.packet(b)
			if _, _, _, _, ok := decodeTCPProbePacket(tt.ipVersion, tt.dstPort, packet); !ok {
				b.Fatal("decodeTCPProbePacket() ok = false")
			}
			b.ReportAllocs()

			for b.Loop() {
				decodeBenchmarkSrcPortSink, decodeBenchmarkSeqSink, decodeBenchmarkAckSink, decodeBenchmarkPeerSink, decodeBenchmarkOKSink = decodeTCPProbePacket(tt.ipVersion, tt.dstPort, packet)
			}
		})
	}
}

func BenchmarkDecodeUDPSocketMessage(b *testing.B) {
	tests := []struct {
		name      string
		ipVersion int
		dstIP     net.IP
		peerIP    net.IP
		srcPort   int
		dstPort   int
	}{
		{
			name:      "IPv4TimeExceeded",
			ipVersion: 4,
			dstIP:     net.ParseIP("192.0.2.9"),
			peerIP:    net.ParseIP("198.51.100.1"),
			srcPort:   40000,
			dstPort:   33494,
		},
		{
			name:      "IPv6TimeExceeded",
			ipVersion: 6,
			dstIP:     net.ParseIP("2001:db8::9"),
			peerIP:    net.ParseIP("2001:db8::1"),
			srcPort:   40001,
			dstPort:   33494,
		},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			inner := benchmarkEmbeddedUDPPacket(tt.ipVersion, tt.dstIP, tt.srcPort, tt.dstPort)
			raw := benchmarkICMPTimeExceeded(b, tt.ipVersion, inner)
			spec := &UDPSpec{IPVersion: tt.ipVersion, DstIP: tt.dstIP, DstPort: tt.dstPort}
			msg := ReceivedMessage{Peer: &net.IPAddr{IP: tt.peerIP}, Msg: raw}
			if _, data, response, ok := spec.decodeICMPSocketMessage(msg); !ok || len(data) != len(inner) || response.Kind != ICMPResponseTransit {
				b.Fatalf("decodeICMPSocketMessage() = (_, %d bytes, %#v, %v), want (_, %d bytes, Transit, true)", len(data), response, ok, len(inner))
			}
			b.SetBytes(int64(len(raw)))
			b.ReportAllocs()

			for b.Loop() {
				decodeBenchmarkFinishSink, decodeBenchmarkDataSink, decodeBenchmarkResponseSink, decodeBenchmarkOKSink = spec.decodeICMPSocketMessage(msg)
			}
		})
	}
}

func BenchmarkPGOProtocolDecodeWorkload(b *testing.B) {
	ipv4Dst := net.ParseIP("192.0.2.9")
	ipv6Dst := net.ParseIP("2001:db8::9")
	ipv4Peer := &net.IPAddr{IP: net.ParseIP("198.51.100.1")}
	ipv6Peer := &net.IPAddr{IP: net.ParseIP("2001:db8::1")}

	icmp4Raw := benchmarkICMPTimeExceeded(b, 4, benchmarkEmbeddedICMPPacket(4, ipv4Dst, 401, 1234))
	icmp6Raw := benchmarkICMPTimeExceeded(b, 6, benchmarkEmbeddedICMPPacket(6, ipv6Dst, 402, 2345))
	icmp4Spec := &ICMPSpec{IPVersion: 4, EchoID: 401, DstIP: ipv4Dst}
	icmp6Spec := &ICMPSpec{IPVersion: 6, EchoID: 402, DstIP: ipv6Dst}
	icmp4Msg := ReceivedMessage{Peer: ipv4Peer, Msg: icmp4Raw}
	icmp6Msg := ReceivedMessage{Peer: ipv6Peer, Msg: icmp6Raw}

	udp4Raw := benchmarkICMPTimeExceeded(b, 4, benchmarkEmbeddedUDPPacket(4, ipv4Dst, 40000, 33494))
	udp6Raw := benchmarkICMPTimeExceeded(b, 6, benchmarkEmbeddedUDPPacket(6, ipv6Dst, 40001, 33494))
	udp4Spec := &UDPSpec{IPVersion: 4, DstIP: ipv4Dst, DstPort: 33494}
	udp6Spec := &UDPSpec{IPVersion: 6, DstIP: ipv6Dst, DstPort: 33494}
	udp4Msg := ReceivedMessage{Peer: ipv4Peer, Msg: udp4Raw}
	udp6Msg := ReceivedMessage{Peer: ipv6Peer, Msg: udp6Raw}

	tcp4Packet := benchmarkSerializeTCPPacket(b, &layers.IPv4{
		Version: 4, IHL: 5, Protocol: layers.IPProtocolTCP,
		SrcIP: net.ParseIP("198.51.100.1").To4(), DstIP: ipv4Dst.To4(),
	}, &layers.TCP{SrcPort: 443, DstPort: 32100, ACK: true, RST: true, Ack: 200})
	tcp6Packet := benchmarkSerializeTCPPacket(b, &layers.IPv6{
		Version: 6, NextHeader: layers.IPProtocolTCP,
		SrcIP: net.ParseIP("2001:db8::1"), DstIP: ipv6Dst,
	}, &layers.TCP{SrcPort: 8443, DstPort: 45678, ACK: true, SYN: true, Ack: 91})

	if _, seq, _, ok := icmp4Spec.decodeICMPSocketMessage(icmp4Msg); !ok || seq != 1234 {
		b.Fatal("IPv4 ICMP workload fixture did not decode")
	}
	if _, seq, _, ok := icmp6Spec.decodeICMPSocketMessage(icmp6Msg); !ok || seq != 2345 {
		b.Fatal("IPv6 ICMP workload fixture did not decode")
	}
	if _, data, _, ok := udp4Spec.decodeICMPSocketMessage(udp4Msg); !ok || len(data) == 0 {
		b.Fatal("IPv4 UDP workload fixture did not decode")
	}
	if _, data, _, ok := udp6Spec.decodeICMPSocketMessage(udp6Msg); !ok || len(data) == 0 {
		b.Fatal("IPv6 UDP workload fixture did not decode")
	}
	if _, _, _, _, ok := decodeTCPProbePacket(4, 443, tcp4Packet); !ok {
		b.Fatal("IPv4 TCP workload fixture did not decode")
	}
	if _, _, _, _, ok := decodeTCPProbePacket(6, 8443, tcp6Packet); !ok {
		b.Fatal("IPv6 TCP workload fixture did not decode")
	}

	b.SetBytes(int64(
		len(icmp4Raw) + len(icmp6Raw) + len(udp4Raw) + len(udp6Raw) +
			len(tcp4Packet.Data()) + len(tcp6Packet.Data()),
	))
	b.ReportAllocs()
	for b.Loop() {
		decodeBenchmarkFinishSink, decodeBenchmarkSeqSink, decodeBenchmarkResponseSink, decodeBenchmarkOKSink = icmp4Spec.decodeICMPSocketMessage(icmp4Msg)
		decodeBenchmarkFinishSink, decodeBenchmarkSeqSink, decodeBenchmarkResponseSink, decodeBenchmarkOKSink = icmp6Spec.decodeICMPSocketMessage(icmp6Msg)
		decodeBenchmarkFinishSink, decodeBenchmarkDataSink, decodeBenchmarkResponseSink, decodeBenchmarkOKSink = udp4Spec.decodeICMPSocketMessage(udp4Msg)
		decodeBenchmarkFinishSink, decodeBenchmarkDataSink, decodeBenchmarkResponseSink, decodeBenchmarkOKSink = udp6Spec.decodeICMPSocketMessage(udp6Msg)
		decodeBenchmarkSrcPortSink, decodeBenchmarkSeqSink, decodeBenchmarkAckSink, decodeBenchmarkPeerSink, decodeBenchmarkOKSink = decodeTCPProbePacket(4, 443, tcp4Packet)
		decodeBenchmarkSrcPortSink, decodeBenchmarkSeqSink, decodeBenchmarkAckSink, decodeBenchmarkPeerSink, decodeBenchmarkOKSink = decodeTCPProbePacket(6, 8443, tcp6Packet)
	}
}

func benchmarkICMPTimeExceeded(b *testing.B, ipVersion int, inner []byte) []byte {
	b.Helper()

	var messageType icmp.Type = ipv4.ICMPTypeTimeExceeded
	if ipVersion == 6 {
		messageType = ipv6.ICMPTypeTimeExceeded
	}
	raw, err := (&icmp.Message{
		Type: messageType,
		Code: 0,
		Body: &icmp.TimeExceeded{Data: inner},
	}).Marshal(nil)
	if err != nil {
		b.Fatalf("marshal ICMP time-exceeded message: %v", err)
	}
	return raw
}

func benchmarkEmbeddedICMPPacket(ipVersion int, dstIP net.IP, echoID, seq int) []byte {
	if ipVersion == 4 {
		packet := make([]byte, 28)
		packet[0] = 0x45
		packet[9] = 1
		copy(packet[16:20], dstIP.To4())
		binary.BigEndian.PutUint16(packet[24:26], uint16(echoID))
		binary.BigEndian.PutUint16(packet[26:28], uint16(seq))
		return packet
	}

	packet := make([]byte, 48)
	packet[0] = 0x60
	packet[6] = 58
	copy(packet[24:40], dstIP.To16())
	binary.BigEndian.PutUint16(packet[44:46], uint16(echoID))
	binary.BigEndian.PutUint16(packet[46:48], uint16(seq))
	return packet
}

func benchmarkEmbeddedUDPPacket(ipVersion int, dstIP net.IP, srcPort, dstPort int) []byte {
	if ipVersion == 4 {
		packet := make([]byte, 28)
		packet[0] = 0x45
		packet[9] = 17
		copy(packet[16:20], dstIP.To4())
		binary.BigEndian.PutUint16(packet[20:22], uint16(srcPort))
		binary.BigEndian.PutUint16(packet[22:24], uint16(dstPort))
		return packet
	}

	packet := make([]byte, 48)
	packet[0] = 0x60
	packet[6] = 17
	copy(packet[24:40], dstIP.To16())
	binary.BigEndian.PutUint16(packet[40:42], uint16(srcPort))
	binary.BigEndian.PutUint16(packet[42:44], uint16(dstPort))
	return packet
}

func benchmarkSerializeTCPPacket(b *testing.B, ipLayer gopacket.NetworkLayer, tcp *layers.TCP) gopacket.Packet {
	b.Helper()

	if err := tcp.SetNetworkLayerForChecksum(ipLayer); err != nil {
		b.Fatalf("set TCP network layer: %v", err)
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	switch ip := ipLayer.(type) {
	case *layers.IPv4:
		if err := gopacket.SerializeLayers(buf, opts, ip, tcp); err != nil {
			b.Fatalf("serialize IPv4 TCP packet: %v", err)
		}
		return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.NoCopy)
	case *layers.IPv6:
		if err := gopacket.SerializeLayers(buf, opts, ip, tcp); err != nil {
			b.Fatalf("serialize IPv6 TCP packet: %v", err)
		}
		return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv6, gopacket.NoCopy)
	default:
		b.Fatalf("unexpected IP layer type %T", ipLayer)
		return nil
	}
}
