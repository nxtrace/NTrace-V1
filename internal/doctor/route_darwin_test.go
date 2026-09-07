//go:build darwin

package doctor

import (
	"errors"
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func TestDarwinRouteReplyEvidence(t *testing.T) {
	m := &route.RouteMessage{Flags: unix.RTF_UP, Addrs: make([]route.Addr, unix.RTAX_MAX)}
	m.Addrs[unix.RTAX_GATEWAY] = &route.LinkAddr{}
	m.Addrs[unix.RTAX_IFP] = &route.LinkAddr{Name: "fixture0"}
	m.Addrs[unix.RTAX_IFA] = &route.Inet4Addr{IP: [4]byte{192, 0, 2, 2}}
	r, e := parseDarwinRoute(m, Route{})
	if e != nil || !r.OnLink || r.Interface != "fixture0" || r.Source != "192.0.2.2" {
		t.Fatalf("%+v %v", r, e)
	}
	m.Flags |= unix.RTF_GATEWAY
	m.Addrs[unix.RTAX_GATEWAY] = &route.Inet6Addr{IP: [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, ZoneID: 7}
	r, e = parseDarwinRoute(m, Route{})
	if e != nil || r.OnLink || r.Gateway != "fe80::1%7" {
		t.Fatalf("%+v %v", r, e)
	}
	for _, err := range []error{unix.ESRCH, unix.ENETUNREACH} {
		m.Err = err
		_, e = parseDarwinRoute(m, Route{})
		if !errors.Is(e, errNoRoute) {
			t.Fatalf("%v", e)
		}
	}
	m.Err = unix.EPERM
	_, e = parseDarwinRoute(m, Route{})
	if e == nil || errors.Is(e, errNoRoute) {
		t.Fatal("permissions misreported as no route")
	}
}
