//go:build linux

package routeprobe

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestLinuxRouteQueryIncludesEffectiveConditions(t *testing.T) {
	for _, dst := range []string{"192.0.2.1", "2001:db8::1"} {
		cfg := Request{Method: "tcp", DstIP: net.ParseIP(dst), FWMark: 0xffffffff, FWMarkSet: true, SrcAddr: dst, SrcPort: 40000, DstPort: 443, TOS: 32}
		b, e := RequestBytes(cfg, 41)
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
		// The standard-library attribute decoder accepts response message
		// types only. The RTM_GETROUTE header above is checked independently;
		// request and response rtmsg attributes share the same layout.
		m.Header.Type = unix.RTM_NEWROUTE
		attrs, e := syscall.ParseNetlinkRouteAttr(&m)
		if e != nil {
			t.Fatal(e)
		}
		seen := map[uint16][]byte{}
		for _, a := range attrs {
			seen[a.Attr.Type] = a.Value
		}
		for _, id := range []uint16{unix.RTA_MARK, unix.RTA_DST, unix.RTA_SRC, unix.RTA_IP_PROTO, unix.RTA_UID, unix.RTA_SPORT, unix.RTA_DPORT} {
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
	r, err := Parse(m, Route{})
	if err != nil || r.Gateway != "192.0.2.254" || r.Source != "192.0.2.2" {
		t.Fatalf("%+v %v", r, err)
	}
	for _, kind := range []byte{unix.RTN_BLACKHOLE, unix.RTN_UNREACHABLE, unix.RTN_PROHIBIT} {
		m.Data[7] = kind
		_, err = Parse(m, Route{})
		if !errors.Is(err, ErrNoRoute) {
			t.Fatalf("route %d: %v", kind, err)
		}
	}
	m.Data = []byte{1}
	_, err = Parse(m, Route{})
	if err == nil || errors.Is(err, ErrNoRoute) {
		t.Fatal("malformed reply treated as no route")
	}
}

func TestLinuxRouteNextHopObjectIsNotAssumedOnLink(t *testing.T) {
	data := make([]byte, 12)
	data[0], data[7] = unix.AF_INET, unix.RTN_UNICAST
	data = append(data, routeAttr(unix.RTA_OIF, routeUint(1))...)
	data = append(data, routeAttr(routeNextHopID, routeUint(42))...)
	m := syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.RTM_NEWROUTE}, Data: data}
	r, err := Parse(m, Route{})
	if err != nil || r.Incomplete == "" || r.OnLink {
		t.Fatalf("unexpanded next hop: %+v %v", r, err)
	}
	via := make([]byte, 2)
	binary.NativeEndian.PutUint16(via, unix.AF_INET6)
	via = append(via, net.ParseIP("2001:db8::1").To16()...)
	m.Data = append(data, routeAttr(unix.RTA_VIA, via)...)
	r, err = Parse(m, Route{})
	if err != nil || r.Gateway != "2001:db8::1" || r.OnLink {
		t.Fatalf("expanded next hop: %+v %v", r, err)
	}
}

func TestRouteMarkPresenceAndWidth(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		for _, mark := range []uint32{0, 0xffffffff} {
			b, err := RequestBytes(Request{Method: "icmp", DstIP: net.ParseIP("127.0.0.1"), FWMark: mark, FWMarkSet: explicit}, 1)
			if err != nil {
				t.Fatal(err)
			}
			msgs, err := syscall.ParseNetlinkMessage(b)
			if err != nil {
				t.Fatal(err)
			}
			msgs[0].Header.Type = unix.RTM_NEWROUTE
			attrs, err := syscall.ParseNetlinkRouteAttr(&msgs[0])
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, a := range attrs {
				if a.Attr.Type == unix.RTA_MARK {
					found = true
					if len(a.Value) != 4 || binary.NativeEndian.Uint32(a.Value) != mark {
						t.Fatal("mark bits lost")
					}
				}
			}
			if found != explicit {
				t.Fatal("omitted/zero mark conflated")
			}
		}
	}
}

func TestRouteOmitsRandomSourcePort(t *testing.T) {
	for _, port := range []int{-1, 0, 40000} {
		b, err := RequestBytes(Request{Method: "tcp", DstIP: net.ParseIP("127.0.0.1"), SrcPort: port, DstPort: 443}, 1)
		if err != nil {
			t.Fatal(err)
		}
		msgs, err := syscall.ParseNetlinkMessage(b)
		if err != nil {
			t.Fatal(err)
		}
		msgs[0].Header.Type = unix.RTM_NEWROUTE
		attrs, err := syscall.ParseNetlinkRouteAttr(&msgs[0])
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, a := range attrs {
			if a.Attr.Type == unix.RTA_SPORT {
				found = true
				if int(binary.BigEndian.Uint16(a.Value)) != port {
					t.Fatal("incorrect source port")
				}
			}
		}
		if found != (port > 0) {
			t.Fatalf("port %d presence %v", port, found)
		}
	}
}

func TestRouteHeaderIncludedProtocol(t *testing.T) {
	for _, tc := range []struct {
		target, method string
		headerIncluded bool
		protocol       byte
		ports          bool
	}{
		{"192.0.2.9", "udp", true, unix.IPPROTO_RAW, false},
		{"192.0.2.9", "udp", false, unix.IPPROTO_UDP, true},
		{"192.0.2.9", "tcp", false, unix.IPPROTO_TCP, true},
		{"192.0.2.9", "icmp", false, unix.IPPROTO_ICMP, false},
		{"2001:db8::9", "udp", true, unix.IPPROTO_UDP, true},
		{"2001:db8::9", "tcp", false, unix.IPPROTO_TCP, true},
		{"2001:db8::9", "icmp", false, unix.IPPROTO_ICMPV6, false},
	} {
		cfg := Request{Method: tc.method, DstIP: net.ParseIP(tc.target), HeaderIncluded: tc.headerIncluded, SrcPort: 40000, DstPort: 443}
		b, err := RequestBytes(cfg, 1)
		if tc.headerIncluded && cfg.DstIP.To4() != nil {
			if err == nil {
				t.Fatal("IPv4 HDRINCL must use the raw socket source lookup, not an unsupported netlink protocol")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		messages, err := syscall.ParseNetlinkMessage(b)
		if err != nil {
			t.Fatal(err)
		}
		messages[0].Header.Type = unix.RTM_NEWROUTE
		attrs, err := syscall.ParseNetlinkRouteAttr(&messages[0])
		if err != nil {
			t.Fatal(err)
		}
		var protocol byte
		ports := 0
		for _, attr := range attrs {
			switch attr.Attr.Type {
			case unix.RTA_IP_PROTO:
				protocol = attr.Value[0]
			case unix.RTA_SPORT, unix.RTA_DPORT:
				ports++
			}
		}
		wantPorts := 0
		if tc.ports {
			wantPorts = 2
		}
		if protocol != tc.protocol || ports != wantPorts {
			t.Fatalf("%+v: kernel protocol=%d ports=%d", tc, protocol, ports)
		}
	}
}

func TestRouteReplyDoneWithoutMatchingRoute(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fds[0]) }()
	defer func() { _ = unix.Close(fds[1]) }()
	message := func(kind uint16, seq uint32) []byte {
		b := make([]byte, unix.NLMSG_HDRLEN)
		binary.NativeEndian.PutUint32(b, uint32(len(b)))
		binary.NativeEndian.PutUint16(b[4:], kind)
		binary.NativeEndian.PutUint32(b[8:], seq)
		return b
	}
	// An unrelated route must not win over the matching completion message.
	data := append(message(unix.RTM_NEWROUTE, 2), message(unix.NLMSG_DONE, 1)...)
	if err := unix.Send(fds[1], data, 0); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	_, err = readRouteReply(ctx, fds[0], Route{})
	if !errors.Is(err, ErrNoRoute) {
		t.Fatalf("got %v, want no route before timeout", err)
	}
}
