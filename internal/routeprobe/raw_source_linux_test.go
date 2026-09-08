//go:build linux

package routeprobe

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestRawSourceCanceledBeforeSocketCreation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	r, err := Query(ctx, Request{Method: "udp", DstIP: net.IPv4(127, 0, 0, 1), HeaderIncluded: true})
	if !errors.Is(err, context.Canceled) || r.Source != "" {
		t.Fatalf("canceled raw lookup: %+v %v", r, err)
	}
}

func TestRawSourceInvalidTargetBeforeSocketCreation(t *testing.T) {
	for _, target := range []net.IP{nil, {127, 0, 1}} {
		r, err := Query(t.Context(), Request{Method: "udp", DstIP: target, HeaderIncluded: true})
		if err == nil || !strings.Contains(err.Error(), "invalid route target") || r.Source != "" {
			t.Fatalf("invalid raw target reached a socket: %+v %v", r, err)
		}
	}
}

func TestRawSourceConfigurationDoesNotIgnoreFailure(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.IPPROTO_UDP)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Close(fd); err != nil {
		t.Fatal(err)
	}
	err = configureRawRouteSocket(fd, Request{TOS: 184})
	if !errors.Is(err, unix.EBADF) || !strings.Contains(err.Error(), "TOS") {
		t.Fatalf("socket option failure was lost: %v", err)
	}
}

// This is a local kernel API check, with no Send/Write calls or probe packets.
func TestRawSourceSocketIntegration(t *testing.T) {
	if os.Getenv("NEXTTRACE_TOS_ROUTE_INTEGRATION") != "1" {
		t.Skip("opt-in privileged raw source-selection socket test")
	}
	for _, tos := range []int{0, 1, 2, 3, 16, 46, 184, 255} {
		for _, mark := range []struct {
			set   bool
			value uint32
		}{{false, 0}, {true, 0}, {true, 0xffffffff}} {
			cfg := Request{Method: "udp", DstIP: net.IPv4(127, 0, 0, 1), TOS: tos, HeaderIncluded: true,
				FWMarkSet: mark.set, FWMark: mark.value, SourceDevice: "lo", SrcAddr: "127.0.0.1", SrcPort: 40000, DstPort: 33494}
			fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
			if err != nil {
				t.Fatal(err)
			}
			if err := disconnectRawRouteSocket(fd); err != nil {
				_ = unix.Close(fd)
				t.Fatal(err)
			}
			if err := configureRawRouteSocket(fd, cfg); err != nil {
				_ = unix.Close(fd)
				t.Fatal(err)
			}
			local, localErr := unix.Getsockname(fd)
			gotTOS, tosErr := unix.GetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TOS)
			gotMark, markErr := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK)
			gotDevice, deviceErr := unix.GetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
			_ = unix.Close(fd)
			addr, ok := local.(*unix.SockaddrInet4)
			if localErr != nil || !ok || addr.Port != 0 || gotTOS != tos || tosErr != nil || uint32(gotMark) != mark.value || markErr != nil || gotDevice != "lo" || deviceErr != nil {
				t.Fatalf("raw socket lost conditions: addr=%+v tos=%d mark=%#x device=%q errors=%v/%v/%v/%v", addr, gotTOS, uint32(gotMark), gotDevice, localErr, tosErr, markErr, deviceErr)
			}
			for _, source := range []string{"", "127.0.0.1"} {
				cfg.SrcAddr = source
				r, err := Query(t.Context(), cfg)
				if err != nil || r.Source != "127.0.0.1" || r.Incomplete == "" || r.Interface != "" || r.Gateway != "" || r.OnLink {
					t.Fatalf("raw source route: %+v %v", r, err)
				}
			}
		}
	}
}
