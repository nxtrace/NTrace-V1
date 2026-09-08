//go:build linux

package doctor

import (
	"net"
	"syscall"
	"testing"

	"github.com/nxtrace/NTrace-core/internal/routeprobe"
	"github.com/nxtrace/NTrace-core/trace"
	"golang.org/x/sys/unix"
)

func TestLinuxDoctorRouteMatchesRawProbeSocket(t *testing.T) {
	for _, target := range []string{"192.0.2.9", "2001:db8::9"} {
		for _, method := range []trace.Method{trace.ICMPTrace, trace.TCPTrace, trace.UDPTrace} {
			cfg := trace.Config{DstIP: net.ParseIP(target), TOS: 184, FWMarkSet: true, FWMark: 256, SrcPort: 40000, DstPort: 443}
			request := linuxProbeRouteRequest(method, cfg)
			if request.TOS != 184 || !request.FWMarkSet || request.FWMark != 256 {
				t.Fatalf("lost doctor route condition: %+v", request)
			}
			b, err := routeprobe.RequestBytes(request, 1)
			if method == trace.UDPTrace && cfg.DstIP.To4() != nil {
				if !request.HeaderIncluded || err == nil {
					t.Fatal("IPv4 UDP doctor must use raw source lookup instead of an unsupported netlink protocol")
				}
				continue
			}
			if request.HeaderIncluded {
				t.Fatal("unexpected raw source lookup for a non-HDRINCL backend")
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
			wantProtocol := byte(unix.IPPROTO_ICMP)
			if cfg.DstIP.To4() == nil {
				wantProtocol = unix.IPPROTO_ICMPV6
			}
			switch method {
			case trace.TCPTrace:
				wantProtocol = unix.IPPROTO_TCP
			case trace.UDPTrace:
				wantProtocol = unix.IPPROTO_UDP
			}
			var gotProtocol byte
			for _, attr := range attrs {
				switch attr.Attr.Type {
				case unix.RTA_IP_PROTO:
					gotProtocol = attr.Value[0]
				case unix.RTA_SPORT, unix.RTA_DPORT:
					t.Fatalf("doctor raw-socket query included transport ports: %+v", request)
				}
			}
			if gotProtocol != wantProtocol {
				t.Fatalf("%s %s: protocol=%d want=%d", target, method, gotProtocol, wantProtocol)
			}
		}
	}
}
