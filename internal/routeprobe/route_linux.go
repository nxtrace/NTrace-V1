//go:build linux

package routeprobe

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// RTA_NH_ID from Linux uapi/linux/rtnetlink.h is absent from x/sys/unix.
const routeNextHopID = 30

func routeAttr(kind uint16, value []byte) []byte {
	n := 4 + len(value)
	b := make([]byte, (n+3)&^3)
	binary.NativeEndian.PutUint16(b, uint16(n))
	binary.NativeEndian.PutUint16(b[2:], kind)
	copy(b[4:], value)
	return b
}

func routeUint(value uint32) []byte {
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, value)
	return b
}

func RequestBytes(cfg Request, seq uint32) ([]byte, error) {
	ip := cfg.DstIP.To4()
	family := byte(unix.AF_INET)
	if ip == nil {
		ip = cfg.DstIP.To16()
		family = unix.AF_INET6
	}
	if ip == nil {
		return nil, errors.New("invalid route target")
	}
	body := make([]byte, 12)
	body[0], body[1], body[3] = family, byte(len(ip)*8), byte(cfg.TOS)
	body = append(body, routeAttr(unix.RTA_DST, ip)...)
	if cfg.FWMarkSet {
		body = append(body, routeAttr(unix.RTA_MARK, routeUint(cfg.FWMark))...)
	}
	if cfg.SrcAddr != "" {
		src := net.ParseIP(cfg.SrcAddr)
		if family == unix.AF_INET {
			src = src.To4()
		} else {
			src = src.To16()
		}
		if src == nil {
			return nil, errors.New("invalid route source")
		}
		body[2] = byte(len(src) * 8)
		body = append(body, routeAttr(unix.RTA_SRC, src)...)
	}
	if cfg.SourceDevice != "" {
		dev, err := net.InterfaceByName(cfg.SourceDevice)
		if err != nil {
			return nil, err
		}
		body = append(body, routeAttr(unix.RTA_OIF, routeUint(uint32(dev.Index)))...)
	}
	proto := byte(unix.IPPROTO_ICMP)
	if family == unix.AF_INET6 {
		proto = unix.IPPROTO_ICMPV6
	}
	switch cfg.Method {
	case "tcp":
		proto = unix.IPPROTO_TCP
	case "udp":
		proto = unix.IPPROTO_UDP
	}
	body = append(body, routeAttr(unix.RTA_IP_PROTO, []byte{proto})...)
	body = append(body, routeAttr(unix.RTA_UID, routeUint(uint32(os.Geteuid())))...)
	if cfg.Method != "icmp" {
		for _, p := range []struct {
			kind uint16
			port int
		}{{unix.RTA_SPORT, cfg.SrcPort}, {unix.RTA_DPORT, cfg.DstPort}} {
			if p.port == 0 {
				continue
			}
			b := make([]byte, 2)
			binary.BigEndian.PutUint16(b, uint16(p.port))
			body = append(body, routeAttr(p.kind, b)...)
		}
	}
	header := make([]byte, 16)
	binary.NativeEndian.PutUint32(header, uint32(len(header)+len(body)))
	binary.NativeEndian.PutUint16(header[4:], unix.RTM_GETROUTE)
	binary.NativeEndian.PutUint16(header[6:], unix.NLM_F_REQUEST)
	binary.NativeEndian.PutUint32(header[8:], seq)
	return append(header, body...), nil
}

func Query(ctx context.Context, cfg Request) (Route, error) {
	r := Route{}
	if cfg.SrcPort == 0 && cfg.Method != "icmp" {
		r.Limitations = "source port selected during probing; ECMP prediction may differ"
	}
	if err := ctx.Err(); err != nil {
		return r, err
	}
	b, err := RequestBytes(cfg, 1)
	if err != nil {
		return r, err
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_ROUTE)
	if err != nil {
		return r, err
	}
	defer func() { _ = unix.Close(fd) }()
	if err = unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return r, err
	}
	if err = unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return r, err
	}
	buf := make([]byte, 65536)
	for {
		n, e := ReadDatagram(ctx, fd, buf)
		if e != nil {
			return r, e
		}
		msgs, e := syscall.ParseNetlinkMessage(buf[:n])
		if e != nil {
			return r, e
		}
		for _, m := range msgs {
			if m.Header.Seq != 1 {
				continue
			}
			if m.Header.Type == unix.NLMSG_ERROR {
				if len(m.Data) < 4 {
					return r, errors.New("short netlink error")
				}
				code := int32(binary.NativeEndian.Uint32(m.Data))
				if code == 0 {
					continue
				}
				err := syscall.Errno(-code)
				if errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) {
					return r, fmt.Errorf("%w: %v", ErrNoRoute, err)
				}
				return r, err
			}
			if m.Header.Type == unix.RTM_NEWROUTE {
				return Parse(m, r)
			}
		}
	}
}

func Parse(m syscall.NetlinkMessage, r Route) (Route, error) {
	if len(m.Data) < 12 {
		return r, errors.New("short route response")
	}
	if m.Data[0] != unix.AF_INET && m.Data[0] != unix.AF_INET6 {
		return r, errors.New("unsupported route address family")
	}
	switch m.Data[7] {
	case unix.RTN_UNREACHABLE, unix.RTN_BLACKHOLE, unix.RTN_PROHIBIT:
		return r, ErrNoRoute
	case unix.RTN_UNICAST, unix.RTN_LOCAL:
	default:
		return r, errors.New("unsupported route type")
	}
	attrs, err := syscall.ParseNetlinkRouteAttr(&m)
	if err != nil {
		return r, err
	}
	nextHopObject := false
	for _, a := range attrs {
		switch a.Attr.Type {
		case unix.RTA_OIF:
			if len(a.Value) != 4 {
				return r, errors.New("invalid route interface")
			}
			idx := int(binary.NativeEndian.Uint32(a.Value))
			if dev, e := net.InterfaceByIndex(idx); e == nil {
				r.Interface = dev.Name
			} else {
				r.Interface = fmt.Sprintf("index %d", idx)
			}
		case unix.RTA_GATEWAY, unix.RTA_PREFSRC:
			n := 4
			if m.Data[0] == unix.AF_INET6 {
				n = 16
			}
			if len(a.Value) != n {
				return r, errors.New("invalid route address")
			}
			if a.Attr.Type == unix.RTA_GATEWAY {
				r.Gateway = net.IP(a.Value).String()
			} else {
				r.Source = net.IP(a.Value).String()
			}
		case unix.RTA_MULTIPATH:
			r.Limitations += "; multiple next hops; actual selection unknown"
			r.Incomplete = "route contains multiple next hops"
		case unix.RTA_VIA:
			if len(a.Value) < 2 {
				return r, errors.New("short route next hop")
			}
			family := binary.NativeEndian.Uint16(a.Value)
			n := 4
			switch family {
			case unix.AF_INET6:
				n = 16
			case unix.AF_INET:
			default:
				return r, errors.New("unsupported next-hop family")
			}
			if len(a.Value) != n+2 {
				return r, errors.New("invalid route next hop")
			}
			r.Gateway = net.IP(a.Value[2:]).String()
		case routeNextHopID:
			nextHopObject = true
		}
	}
	if nextHopObject && r.Gateway == "" {
		r.Incomplete = "next-hop object was not expanded by the kernel"
	}
	r.OnLink = r.Incomplete == "" && r.Gateway == "" && r.Interface != ""
	return r, nil
}
