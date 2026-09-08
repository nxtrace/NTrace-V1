package internal

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"golang.org/x/net/ipv4"
)

// A closed ordinary UDP socket makes the real setsockopt path fail without
// requiring raw-socket privileges or sending any packet.
func closedTOSSocket(t *testing.T) net.PacketConn {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	return conn
}

func assertTOSSetupFailure(t *testing.T, start time.Time, err error, field string) {
	t.Helper()
	var setup *InitializationError
	if !errors.As(err, &setup) {
		t.Fatalf("error = %v (%T), want InitializationError", err, err)
	}
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("error = %v, want preserved closed-socket cause", err)
	}
	if !strings.Contains(err.Error(), field+" 184") || !start.IsZero() {
		t.Fatalf("start=%v error=%v, want unsent packet and field/value diagnostic", start, err)
	}
}

func TestICMPv4TOSFailureIsInitializationError(t *testing.T) {
	conn := closedTOSSocket(t)
	s := ICMPSpec{IPVersion: 4, icmp: conn, icmp4: ipv4.NewPacketConn(conn)}
	hdr := &layers.IPv4{Version: 4, TOS: 184, TTL: 1}
	start, err := s.SendICMP(t.Context(), hdr, &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(8, 0)}, nil, nil)
	assertTOSSetupFailure(t, start, err, "IPv4 TOS")
}
