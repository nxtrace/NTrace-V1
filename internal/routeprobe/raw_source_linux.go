//go:build linux

package routeprobe

import (
	"context"
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// RTM_GETROUTE accepts only selected transport protocols, excluding RAW (255).
// A raw socket connect performs the matching kernel lookup without emitting a
// packet. It exposes the chosen source, but not the route interface or gateway.
func queryRawSource(ctx context.Context, cfg Request) (Route, error) {
	r := Route{}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.IPPROTO_RAW)
	if err != nil {
		return r, fmt.Errorf("open raw source-selection socket: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()
	// Linux initializes inet_sport to the raw protocol number. AF_UNSPEC
	// disconnect clears that artificial port before the route lookup, matching
	// raw_sendmsg's zero transport ports. Apply source/device options afterwards.
	if err := disconnectRawRouteSocket(fd); err != nil {
		return r, fmt.Errorf("clear raw route source port: %w", err)
	}
	local, err := unix.Getsockname(fd)
	if err != nil {
		return r, err
	}
	if addr, ok := local.(*unix.SockaddrInet4); !ok || addr.Port != 0 {
		return r, errors.New("raw route socket did not clear its source port")
	}
	if err := configureRawRouteSocket(fd, cfg); err != nil {
		return r, err
	}
	if err := ctx.Err(); err != nil {
		return r, err
	}
	target := &unix.SockaddrInet4{}
	copy(target.Addr[:], cfg.DstIP.To4())
	if err := unix.Connect(fd, target); err != nil {
		if errors.Is(err, unix.ENETUNREACH) || errors.Is(err, unix.EHOSTUNREACH) || errors.Is(err, unix.EACCES) {
			return r, fmt.Errorf("%w: %w", ErrNoRoute, err)
		}
		return r, err
	}
	if err := ctx.Err(); err != nil {
		return r, err
	}
	local, err = unix.Getsockname(fd)
	if err != nil {
		return r, err
	}
	addr, ok := local.(*unix.SockaddrInet4)
	if !ok || addr.Port != 0 || net.IP(addr.Addr[:]).IsUnspecified() {
		return r, errors.New("raw route socket did not select a usable source with zero transport ports")
	}
	r.Source = net.IP(addr.Addr[:]).String()
	r.Incomplete = "raw socket selected the source; route interface and gateway are unavailable"
	return r, nil
}

func configureRawRouteSocket(fd int, cfg Request) error {
	if cfg.TOS < 0 || cfg.TOS > 255 {
		return errors.New("TOS must be between 0 and 255")
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TOS, cfg.TOS); err != nil {
		return fmt.Errorf("set raw source-selection TOS: %w", err)
	}
	if cfg.FWMarkSet {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, int(cfg.FWMark)); err != nil {
			return fmt.Errorf("set raw source-selection fwmark: %w", err)
		}
	}
	if cfg.SourceDevice != "" {
		if err := unix.BindToDevice(fd, cfg.SourceDevice); err != nil {
			return fmt.Errorf("bind raw source-selection device: %w", err)
		}
	}
	if cfg.SrcAddr != "" {
		ip := net.ParseIP(cfg.SrcAddr).To4()
		if ip == nil || ip.IsUnspecified() {
			return errors.New("invalid raw route source")
		}
		source := &unix.SockaddrInet4{}
		copy(source.Addr[:], ip)
		if err := unix.Bind(fd, source); err != nil {
			return fmt.Errorf("bind raw source-selection address: %w", err)
		}
	}
	return nil
}
