//go:build linux

package doctor

import (
	"encoding/binary"
	"errors"
	"net"
	"syscall"
	"testing"

	"github.com/nxtrace/NTrace-core/trace"
	"golang.org/x/sys/unix"
)

func TestLinuxRouteQueryIncludesEffectiveConditions(t *testing.T) {
	for _, dst := range []string{"192.0.2.1", "2001:db8::1"} {
		cfg := trace.Config{DstIP: net.ParseIP(dst), SrcAddr: dst, SrcPort: 40000, DstPort: 443, TOS: 32}
		b, e := linuxRouteRequest(trace.TCPTrace, cfg, 41)
		if e != nil {
			t.Fatal(e)
		}
		msgs, e := syscall.ParseNetlinkMessage(b)
		if e != nil || len(msgs) != 1 {
			t.Fatalf("%v", e)
		}
		m := msgs[0]
		if m.Header.Seq != 41 || m.Header.Type != unix.RTM_GETROUTE || m.Header.Flags != unix.NLM_F_REQUEST || m.Data[3] != 32 {
			t.Fatalf("wrong request: %+v", m)
		}
		attrs, e := syscall.ParseNetlinkRouteAttr(&m)
		if e != nil {
			t.Fatal(e)
		}
		seen := map[uint16][]byte{}
		for _, a := range attrs {
			seen[a.Attr.Type] = a.Value
		}
		for _, id := range []uint16{unix.RTA_DST, unix.RTA_SRC, unix.RTA_IP_PROTO, unix.RTA_UID, unix.RTA_SPORT, unix.RTA_DPORT} {
			if seen[id] == nil {
				t.Fatalf("missing %d", id)
			}
		}
		if binary.BigEndian.Uint16(seen[unix.RTA_SPORT]) != 40000 || binary.BigEndian.Uint16(seen[unix.RTA_DPORT]) != 443 {
			t.Fatal("port byte order")
		}
	}
}

func TestLinuxRouteResponseDistinguishesRejectAndMalformed(t *testing.T) {
	data := make([]byte, 12)
	data[0] = unix.AF_INET
	data[7] = unix.RTN_UNICAST
	data = append(data, routeAttr(unix.RTA_GATEWAY, net.IPv4(192, 0, 2, 254).To4())...)
	data = append(data, routeAttr(unix.RTA_PREFSRC, net.IPv4(192, 0, 2, 2).To4())...)
	m := syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.RTM_NEWROUTE}, Data: data}
	r, err := parseLinuxRoute(m, Route{})
	if err != nil || r.Gateway != "192.0.2.254" || r.Source != "192.0.2.2" {
		t.Fatalf("%+v %v", r, err)
	}
	for _, kind := range []byte{unix.RTN_BLACKHOLE, unix.RTN_UNREACHABLE, unix.RTN_PROHIBIT} {
		m.Data[7] = kind
		_, err = parseLinuxRoute(m, Route{})
		if !errors.Is(err, errNoRoute) {
			t.Fatalf("route %d: %v", kind, err)
		}
	}
	m.Data = []byte{1}
	_, err = parseLinuxRoute(m, Route{})
	if err == nil || errors.Is(err, errNoRoute) {
		t.Fatal("malformed reply treated as no route")
	}
}
