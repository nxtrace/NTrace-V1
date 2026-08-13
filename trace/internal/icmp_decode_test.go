package internal

import (
	"encoding/binary"
	"net"
	"testing"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func mustMarshalICMP(t *testing.T, message icmp.Message) []byte {
	t.Helper()
	raw, err := message.Marshal(nil)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	return raw
}

func buildIPv4InnerPacket(dstIP net.IP, echoID, seq int) []byte {
	packet := make([]byte, 28)
	packet[0] = 0x45
	copy(packet[16:20], dstIP.To4())
	binary.BigEndian.PutUint16(packet[24:26], uint16(echoID))
	binary.BigEndian.PutUint16(packet[26:28], uint16(seq))
	return packet
}

func buildIPv6InnerPacket(dstIP net.IP, echoID, seq int) []byte {
	packet := make([]byte, 48)
	packet[0] = 0x60
	packet[6] = 58
	copy(packet[24:40], dstIP.To16())
	binary.BigEndian.PutUint16(packet[44:46], uint16(echoID))
	binary.BigEndian.PutUint16(packet[46:48], uint16(seq))
	return packet
}

func TestMatchSocketICMPEchoReplyIPv4(t *testing.T) {
	dstIP := net.ParseIP("192.0.2.1")
	raw := mustMarshalICMP(t, icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Code: 0,
		Body: &icmp.Echo{ID: 7, Seq: 11},
	})

	rm, ok := parseSocketICMPMessage(4, raw)
	if !ok {
		t.Fatalf("parseSocketICMPMessage() ok = false")
	}
	seq, ok := matchSocketICMPEchoReply(4, rm, 7, &net.IPAddr{IP: dstIP}, dstIP)
	if !ok || seq != 11 {
		t.Fatalf("matchSocketICMPEchoReply() = (%d, %v), want (11, true)", seq, ok)
	}
}

func TestMatchSocketICMPEchoReplyIPv6(t *testing.T) {
	dstIP := net.ParseIP("2001:db8::1")
	raw := mustMarshalICMP(t, icmp.Message{
		Type: ipv6.ICMPTypeEchoReply,
		Code: 0,
		Body: &icmp.Echo{ID: 9, Seq: 21},
	})

	rm, ok := parseSocketICMPMessage(6, raw)
	if !ok {
		t.Fatalf("parseSocketICMPMessage() ok = false")
	}
	seq, ok := matchSocketICMPEchoReply(6, rm, 9, &net.IPAddr{IP: dstIP}, dstIP)
	if !ok || seq != 21 {
		t.Fatalf("matchSocketICMPEchoReply() = (%d, %v), want (21, true)", seq, ok)
	}
}

func TestDecodeICMPSocketEchoReplyRejectsNonDestinationSourceIP(t *testing.T) {
	raw := mustMarshalICMP(t, icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Code: 0,
		Body: &icmp.Echo{ID: 7, Seq: 11},
	})
	spec := &ICMPSpec{
		IPVersion: 4,
		EchoID:    7,
		DstIP:     net.ParseIP("192.0.2.1"),
	}
	_, _, _, ok := spec.decodeICMPSocketMessage(ReceivedMessage{
		Peer: &net.IPAddr{IP: net.ParseIP("192.0.2.2")},
		Msg:  raw,
	})
	if ok {
		t.Fatal("decodeICMPSocketMessage() ok = true, want false for non-destination Echo Reply source")
	}
}

func TestDecodeICMPSocketErrorAllowsAlternateOuterSource(t *testing.T) {
	tests := []struct {
		name      string
		ipVersion int
		dstIP     net.IP
		peerIP    net.IP
		echoID    int
		seq       int
		message   icmp.Message
	}{
		{
			name:      "IPv4",
			ipVersion: 4,
			dstIP:     net.ParseIP("192.0.2.1"),
			peerIP:    net.ParseIP("198.51.100.1"),
			echoID:    7,
			seq:       11,
			message: icmp.Message{Type: ipv4.ICMPTypeTimeExceeded, Code: 0, Body: &icmp.TimeExceeded{
				Data: buildIPv4InnerPacket(net.ParseIP("192.0.2.1"), 7, 11),
			}},
		},
		{
			name:      "IPv6",
			ipVersion: 6,
			dstIP:     net.ParseIP("2001:db8::1"),
			peerIP:    net.ParseIP("2001:db8::ffff"),
			echoID:    9,
			seq:       21,
			message: icmp.Message{Type: ipv6.ICMPTypeTimeExceeded, Code: 0, Body: &icmp.TimeExceeded{
				Data: buildIPv6InnerPacket(net.ParseIP("2001:db8::1"), 9, 21),
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := &ICMPSpec{IPVersion: tt.ipVersion, EchoID: tt.echoID, DstIP: tt.dstIP}
			_, seq, response, ok := spec.decodeICMPSocketMessage(ReceivedMessage{
				Peer: &net.IPAddr{IP: tt.peerIP},
				Msg:  mustMarshalICMP(t, tt.message),
			})
			if !ok || seq != tt.seq || response.Kind != ICMPResponseTransit {
				t.Fatalf("decodeICMPSocketMessage() = (_, %d, %#v, %v), want (_, %d, Transit, true)", seq, response, ok, tt.seq)
			}
		})
	}
}

func TestDecodeICMPSocketErrorRejectsWrongEmbeddedIdentifier(t *testing.T) {
	dstIP := net.ParseIP("192.0.2.1")
	raw := mustMarshalICMP(t, icmp.Message{
		Type: ipv4.ICMPTypeTimeExceeded,
		Code: 0,
		Body: &icmp.TimeExceeded{Data: buildIPv4InnerPacket(dstIP, 8, 11)},
	})
	spec := &ICMPSpec{IPVersion: 4, EchoID: 7, DstIP: dstIP}
	if _, _, _, ok := spec.decodeICMPSocketMessage(ReceivedMessage{
		Peer: &net.IPAddr{IP: net.ParseIP("198.51.100.1")},
		Msg:  raw,
	}); ok {
		t.Fatal("decodeICMPSocketMessage() ok = true, want false for wrong embedded Echo ID")
	}
}

func TestClassifySocketICMPResponse(t *testing.T) {
	tests := []struct {
		name       string
		ipVersion  int
		message    icmp.Message
		wantKind   ICMPResponseKind
		wantDetail string
		wantMarker string
	}{
		{
			name:       "IPv4 transit",
			ipVersion:  4,
			message:    icmp.Message{Type: ipv4.ICMPTypeTimeExceeded, Code: 0, Body: &icmp.TimeExceeded{}},
			wantKind:   ICMPResponseTransit,
			wantDetail: "ICMP Time Exceeded",
		},
		{
			name:       "IPv4 fragment reassembly timeout",
			ipVersion:  4,
			message:    icmp.Message{Type: ipv4.ICMPTypeTimeExceeded, Code: 1, Body: &icmp.TimeExceeded{}},
			wantKind:   ICMPResponseUnreachable,
			wantDetail: "ICMP Fragment Reassembly Time Exceeded",
			wantMarker: "!<11-1>",
		},
		{
			name:       "IPv4 unknown time exceeded code",
			ipVersion:  4,
			message:    icmp.Message{Type: ipv4.ICMPTypeTimeExceeded, Code: 2, Body: &icmp.TimeExceeded{}},
			wantKind:   ICMPResponseUnreachable,
			wantDetail: "ICMP Time Exceeded (Code 2)",
			wantMarker: "!<11-2>",
		},
		{
			name:       "IPv4 host unreachable",
			ipVersion:  4,
			message:    icmp.Message{Type: ipv4.ICMPTypeDestinationUnreachable, Code: 1, Body: &icmp.DstUnreach{}},
			wantKind:   ICMPResponseUnreachable,
			wantDetail: "ICMP Host Unreachable",
			wantMarker: "!H",
		},
		{
			name:       "IPv4 port unreachable",
			ipVersion:  4,
			message:    icmp.Message{Type: ipv4.ICMPTypeDestinationUnreachable, Code: 3, Body: &icmp.DstUnreach{}},
			wantKind:   ICMPResponsePortUnreachable,
			wantDetail: "ICMP Port Unreachable",
			wantMarker: "!<3-3>",
		},
		{
			name:       "IPv6 port unreachable",
			ipVersion:  6,
			message:    icmp.Message{Type: ipv6.ICMPTypeDestinationUnreachable, Code: 4, Body: &icmp.DstUnreach{}},
			wantKind:   ICMPResponsePortUnreachable,
			wantDetail: "ICMPv6 Port Unreachable",
			wantMarker: "!<1-4>",
		},
		{
			name:       "IPv6 administratively prohibited",
			ipVersion:  6,
			message:    icmp.Message{Type: ipv6.ICMPTypeDestinationUnreachable, Code: 1, Body: &icmp.DstUnreach{}},
			wantKind:   ICMPResponseUnreachable,
			wantDetail: "ICMPv6 Administratively Prohibited",
			wantMarker: "!X",
		},
		{
			name:       "IPv6 transit",
			ipVersion:  6,
			message:    icmp.Message{Type: ipv6.ICMPTypeTimeExceeded, Code: 0, Body: &icmp.TimeExceeded{}},
			wantKind:   ICMPResponseTransit,
			wantDetail: "ICMPv6 Time Exceeded",
		},
		{
			name:       "IPv6 fragment reassembly timeout",
			ipVersion:  6,
			message:    icmp.Message{Type: ipv6.ICMPTypeTimeExceeded, Code: 1, Body: &icmp.TimeExceeded{}},
			wantKind:   ICMPResponseUnreachable,
			wantDetail: "ICMPv6 Fragment Reassembly Time Exceeded",
			wantMarker: "!<3-1>",
		},
		{
			name:       "IPv6 unknown time exceeded code",
			ipVersion:  6,
			message:    icmp.Message{Type: ipv6.ICMPTypeTimeExceeded, Code: 2, Body: &icmp.TimeExceeded{}},
			wantKind:   ICMPResponseUnreachable,
			wantDetail: "ICMPv6 Time Exceeded (Code 2)",
			wantMarker: "!<3-2>",
		},
		{
			name:       "IPv6 beyond scope",
			ipVersion:  6,
			message:    icmp.Message{Type: ipv6.ICMPTypeDestinationUnreachable, Code: 2, Body: &icmp.DstUnreach{}},
			wantKind:   ICMPResponseUnreachable,
			wantDetail: "ICMPv6 Beyond Scope of Source Address",
			wantMarker: "!H",
		},
		{
			name:       "IPv6 address unreachable",
			ipVersion:  6,
			message:    icmp.Message{Type: ipv6.ICMPTypeDestinationUnreachable, Code: 3, Body: &icmp.DstUnreach{}},
			wantKind:   ICMPResponseUnreachable,
			wantDetail: "ICMPv6 Address Unreachable",
			wantMarker: "!H",
		},
		{
			name:       "IPv6 packet too big",
			ipVersion:  6,
			message:    icmp.Message{Type: ipv6.ICMPTypePacketTooBig, Code: 0, Body: &icmp.PacketTooBig{MTU: 1280}},
			wantKind:   ICMPResponseUnreachable,
			wantDetail: "ICMPv6 Packet Too Big",
			wantMarker: "!F-1280",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := mustMarshalICMP(t, tt.message)
			rm, ok := parseSocketICMPMessage(tt.ipVersion, raw)
			if !ok {
				t.Fatalf("parseSocketICMPMessage() ok = false")
			}
			got := classifySocketICMPResponse(tt.ipVersion, rm, raw)
			if got.Kind != tt.wantKind || got.Description != tt.wantDetail || got.Marker != tt.wantMarker {
				t.Fatalf("classifySocketICMPResponse() = (%v, %q, %q), want (%v, %q, %q)", got.Kind, got.Description, got.Marker, tt.wantKind, tt.wantDetail, tt.wantMarker)
			}
		})
	}
}

func TestExtractSocketICMPPayloadIPv4(t *testing.T) {
	dstIP := net.ParseIP("8.8.8.8")
	inner := buildIPv4InnerPacket(dstIP, 13, 99)
	raw := mustMarshalICMP(t, icmp.Message{
		Type: ipv4.ICMPTypeTimeExceeded,
		Code: 0,
		Body: &icmp.TimeExceeded{Data: inner},
	})

	rm, ok := parseSocketICMPMessage(4, raw)
	if !ok {
		t.Fatalf("parseSocketICMPMessage() ok = false")
	}
	data, ok := extractSocketICMPPayload(4, rm, dstIP)
	if !ok {
		t.Fatalf("extractSocketICMPPayload() ok = false")
	}
	if seq, ok := extractEmbeddedICMPSeq(data, 13); !ok || seq != 99 {
		t.Fatalf("extractEmbeddedICMPSeq() = (%d, %v), want (99, true)", seq, ok)
	}
}

func TestExtractSocketICMPPayloadIPv6(t *testing.T) {
	dstIP := net.ParseIP("2001:db8::2")
	inner := buildIPv6InnerPacket(dstIP, 17, 123)
	raw := mustMarshalICMP(t, icmp.Message{
		Type: ipv6.ICMPTypeDestinationUnreachable,
		Code: 0,
		Body: &icmp.DstUnreach{Data: inner},
	})

	rm, ok := parseSocketICMPMessage(6, raw)
	if !ok {
		t.Fatalf("parseSocketICMPMessage() ok = false")
	}
	data, ok := extractSocketICMPPayload(6, rm, dstIP)
	if !ok {
		t.Fatalf("extractSocketICMPPayload() ok = false")
	}
	if seq, ok := extractEmbeddedICMPSeq(data, 17); !ok || seq != 123 {
		t.Fatalf("extractEmbeddedICMPSeq() = (%d, %v), want (123, true)", seq, ok)
	}
}

func TestExtractSocketICMPPayloadRejectsWrongDestination(t *testing.T) {
	raw := mustMarshalICMP(t, icmp.Message{
		Type: ipv4.ICMPTypeDestinationUnreachable,
		Code: 0,
		Body: &icmp.DstUnreach{Data: buildIPv4InnerPacket(net.ParseIP("9.9.9.9"), 3, 5)},
	})

	rm, ok := parseSocketICMPMessage(4, raw)
	if !ok {
		t.Fatalf("parseSocketICMPMessage() ok = false")
	}
	if _, ok := extractSocketICMPPayload(4, rm, net.ParseIP("8.8.8.8")); ok {
		t.Fatalf("extractSocketICMPPayload() ok = true, want false")
	}
}
