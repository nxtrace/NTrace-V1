//go:build !darwin && !(windows && amd64)

package internal

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/google/gopacket/layers"
	"golang.org/x/net/ipv4"
)

func TestUDPv4RawTOSFailureIsInitializationError(t *testing.T) {
	// An unavailable RawConn fails before WriteTo without requiring raw socket
	// privileges. The privileged reuse fixture also tests a real closed socket.
	s := UDPSpec{IPVersion: 4, udp4: &ipv4.RawConn{}, mtu: 1500}
	hdr := &layers.IPv4{Version: 4, TOS: 184, TTL: 1, Protocol: layers.IPProtocolUDP, SrcIP: net.IPv4(127, 0, 0, 1), DstIP: net.IPv4(127, 0, 0, 1)}
	start, err := s.SendUDP(t.Context(), hdr, &layers.UDP{}, nil)
	var setup *InitializationError
	if !errors.As(err, &setup) || !strings.Contains(err.Error(), "IPv4 TOS 184") || !start.IsZero() {
		t.Fatalf("start=%v error=%v, want unsent packet and TOS initialization error", start, err)
	}
}
