//go:build darwin

package doctor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/nxtrace/NTrace-core/trace"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func queryRoute(ctx context.Context, method trace.Method, cfg trace.Config) (Route, error) {
	r := Route{Conditions: fmt.Sprintf("dst=%s dev=%s", cfg.DstIP, cfg.SourceDevice), Limitations: "source policy, protocol, ports and TOS are not included in this route query"}
	if err := ctx.Err(); err != nil {
		return r, err
	}
	msg := route.RouteMessage{Version: unix.RTM_VERSION, Type: unix.RTM_GET, Flags: unix.RTF_UP | unix.RTF_HOST, ID: uintptr(os.Getpid()), Seq: 1, Addrs: make([]route.Addr, unix.RTAX_MAX)}
	if ip := cfg.DstIP.To4(); ip != nil {
		a := &route.Inet4Addr{}
		copy(a.IP[:], ip)
		msg.Addrs[unix.RTAX_DST] = a
	} else {
		a := &route.Inet6Addr{}
		copy(a.IP[:], cfg.DstIP.To16())
		msg.Addrs[unix.RTAX_DST] = a
	}
	msg.Addrs[unix.RTAX_IFP] = &route.LinkAddr{}
	if cfg.SourceDevice != "" {
		dev, err := net.InterfaceByName(cfg.SourceDevice)
		if err != nil {
			return r, err
		}
		msg.Index = dev.Index
		msg.Flags |= unix.RTF_IFSCOPE
	}
	b, err := msg.Marshal()
	if err != nil {
		return r, err
	}
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return r, err
	}
	defer func() { _ = unix.Close(fd) }()
	unix.CloseOnExec(fd)
	if err = unix.SetNonblock(fd, true); err != nil {
		return r, err
	}
	if _, err = unix.Write(fd, b); err != nil {
		return r, darwinRouteError(err)
	}
	buf := make([]byte, 65536)
	for {
		n, e := readRouteDatagram(ctx, fd, buf)
		if e != nil {
			return r, e
		}
		msgs, e := route.ParseRIB(route.RIBTypeRoute, buf[:n])
		if e != nil {
			return r, e
		}
		for _, m := range msgs {
			rm, ok := m.(*route.RouteMessage)
			if !ok || rm.Type != unix.RTM_GET || rm.Seq != msg.Seq || rm.ID != msg.ID {
				continue
			}
			return parseDarwinRoute(rm, r)
		}
	}
}

func darwinRouteError(err error) error {
	if errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ENETUNREACH) || errors.Is(err, unix.EHOSTUNREACH) {
		return fmt.Errorf("%w: %v", errNoRoute, err)
	}
	return err
}

func darwinRouteIP(a route.Addr) string {
	switch a := a.(type) {
	case *route.Inet4Addr:
		return net.IP(a.IP[:]).String()
	case *route.Inet6Addr:
		s := net.IP(a.IP[:]).String()
		if a.ZoneID != 0 {
			s += fmt.Sprintf("%%%d", a.ZoneID)
		}
		return s
	}
	return ""
}

func parseDarwinRoute(m *route.RouteMessage, r Route) (Route, error) {
	if m.Err != nil {
		return r, darwinRouteError(m.Err)
	}
	if m.Flags&(unix.RTF_REJECT|unix.RTF_BLACKHOLE) != 0 {
		return r, errNoRoute
	}
	if m.Index != 0 {
		if d, e := net.InterfaceByIndex(m.Index); e == nil {
			r.Interface = d.Name
		} else {
			r.Interface = fmt.Sprintf("index %d", m.Index)
		}
	}
	for i, a := range m.Addrs {
		switch i {
		case unix.RTAX_GATEWAY:
			r.Gateway = darwinRouteIP(a)
			_, link := a.(*route.LinkAddr)
			r.OnLink = link && m.Flags&unix.RTF_GATEWAY == 0
		case unix.RTAX_IFA:
			r.Source = darwinRouteIP(a)
		case unix.RTAX_IFP:
			if a, ok := a.(*route.LinkAddr); ok && a.Name != "" {
				r.Interface = a.Name
			}
		}
	}
	return r, nil
}
