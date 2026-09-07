//go:build windows

package doctor

import (
	"context"
	"fmt"
	"net"
	"unsafe"

	"github.com/nxtrace/NTrace-core/trace"
	"golang.org/x/sys/windows"
)

var getBestRoute2 = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetBestRoute2")

func windowsRouteAddress(ip net.IP) windows.RawSockaddrInet {
	var addr windows.RawSockaddrInet
	if v4 := ip.To4(); v4 != nil {
		a := (*windows.RawSockaddrInet4)(unsafe.Pointer(&addr))
		a.Family = windows.AF_INET
		copy(a.Addr[:], v4)
	} else {
		a := (*windows.RawSockaddrInet6)(unsafe.Pointer(&addr))
		a.Family = windows.AF_INET6
		copy(a.Addr[:], ip.To16())
	}
	return addr
}

func windowsRouteIP(addr *windows.RawSockaddrInet) net.IP {
	if addr.Family == windows.AF_INET {
		a := (*windows.RawSockaddrInet4)(unsafe.Pointer(addr))
		return append(net.IP(nil), a.Addr[:]...)
	}
	if addr.Family == windows.AF_INET6 {
		a := (*windows.RawSockaddrInet6)(unsafe.Pointer(addr))
		return append(net.IP(nil), a.Addr[:]...)
	}
	return nil
}

func queryRoute(ctx context.Context, method trace.Method, cfg trace.Config) (Route, error) {
	r := Route{Conditions: fmt.Sprintf("dst=%s source=%s", cfg.DstIP, cfg.SrcAddr), Limitations: "protocol, ports and TOS are not included; --dev selects a source address, not an interface binding"}
	if err := ctx.Err(); err != nil {
		return r, err
	}
	if err := getBestRoute2.Find(); err != nil {
		return r, err
	}
	dst := windowsRouteAddress(cfg.DstIP)
	var src *windows.RawSockaddrInet
	if cfg.SrcAddr != "" {
		a := windowsRouteAddress(net.ParseIP(cfg.SrcAddr))
		src = &a
	}
	var row windows.MibIpForwardRow2
	var best windows.RawSockaddrInet
	// This local synchronous OS call has no cancellation API. Do not abandon it
	// in a goroutine and claim that native resources have been reclaimed.
	code, _, _ := getBestRoute2.Call(0, 0, uintptr(unsafe.Pointer(src)), uintptr(unsafe.Pointer(&dst)), 0, uintptr(unsafe.Pointer(&row)), uintptr(unsafe.Pointer(&best)))
	if err := ctx.Err(); err != nil {
		return r, err
	}
	if code != 0 {
		err := windows.Errno(code)
		if err == windows.ERROR_NETWORK_UNREACHABLE || err == windows.ERROR_HOST_UNREACHABLE || err == windows.ERROR_NOT_FOUND {
			return r, fmt.Errorf("%w: %v", errNoRoute, err)
		}
		return r, err
	}
	if dev, err := net.InterfaceByIndex(int(row.InterfaceIndex)); err == nil {
		r.Interface = dev.Name
	} else {
		r.Interface = fmt.Sprintf("index %d", row.InterfaceIndex)
	}
	if ip := windowsRouteIP(&best); ip != nil {
		r.Source = ip.String()
	}
	if ip := windowsRouteIP(&row.NextHop); ip != nil {
		r.OnLink = ip.IsUnspecified()
		if !r.OnLink {
			r.Gateway = ip.String()
		}
	}
	return r, nil
}
