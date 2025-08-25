//go:build darwin

package internal

import (
	"errors"
	"net"
	"os"
	"strings"
	"syscall"

	"github.com/nxtrace/NTrace-core/util"
)

var (
	errUnknownNetwork   = errors.New("unknown network type")
	errUnknownIface     = errors.New("unknown network interface")
	errIPFamilyMismatch = errors.New("address and network family mismatch")
)

// afProtoFromNetwork 从传入的 network 字符串判断地址族与协议号：仅支持 ICMPv4(1) 与 ICMPv6(58)
func afProtoFromNetwork(network string) (af, proto int, ok bool) {
	switch network {
	case "ip4:icmp", "ip4:1":
		return syscall.AF_INET, syscall.IPPROTO_ICMP, true
	case "ip6:ipv6-icmp", "ip6:58":
		return syscall.AF_INET6, syscall.IPPROTO_ICMPV6, true
	default:
		return 0, 0, false
	}
}

// parseIPStripZone 解析 IP 字符串，仅保留纯 IP 部分
func parseIPStripZone(address string) net.IP {
	address = strings.TrimSpace(address)
	if i := strings.IndexByte(address, '%'); i >= 0 {
		address = address[:i]
	}
	return net.ParseIP(address)
}

// ifaceIndexFromAddress 使用 util.FindDeviceByIP 找到接口名并转为 ifIndex
func ifaceIndexFromAddress(address string) (int, error) {
	if address == "" {
		return -1, nil
	}
	ip := parseIPStripZone(address)
	if ip == nil {
		return -1, errUnknownIface
	}
	name := util.FindDeviceByIP(ip)
	if name == "" {
		return -1, errUnknownIface
	}
	ifi, err := net.InterfaceByName(name)
	if err != nil || ifi.Index <= 0 {
		return -1, errUnknownIface
	}
	return ifi.Index, nil
}

// ListenPacket 通过 syscall.Socket 创建 ICMP DGRAM ping socket
func ListenPacket(network string, address string) (net.PacketConn, error) {
	af, proto, ok := afProtoFromNetwork(network)
	if !ok {
		return nil, errUnknownNetwork
	}

	// 如传入 address，校验其与 family 的匹配关系
	var ip net.IP
	if address != "" {
		ip = parseIPStripZone(address)
		if ip == nil {
			return nil, errUnknownIface
		}
		if af == syscall.AF_INET && ip.To4() == nil {
			return nil, errIPFamilyMismatch
		}
		if af == syscall.AF_INET6 && (ip.To16() == nil || ip.To4() != nil) {
			return nil, errIPFamilyMismatch
		}
	}

	// 需要绑定接口时，先取 ifIndex
	ifIndex := -1
	var err error
	if address != "" {
		ifIndex, err = ifaceIndexFromAddress(address)
		if err != nil {
			return nil, err
		}
	}

	// 创建 ICMP/ICMPv6 的 DGRAM 套接字（非 RAW）
	fd, err := syscall.Socket(af, syscall.SOCK_DGRAM, proto)
	if err != nil {
		return nil, os.NewSyscallError("socket", err)
	}

	var retErr error
	defer func() {
		if retErr != nil {
			_ = syscall.Close(fd)
		}
	}()
	syscall.CloseOnExec(fd)

	// 若指定了 address，则：先绑定接口，再绑定源 IP
	if address != "" {
		switch af {
		case syscall.AF_INET:
			// 绑定接口
			if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_BOUND_IF, ifIndex); err != nil {
				retErr = os.NewSyscallError("setsockopt(IP_BOUND_IF)", err)
				return nil, retErr
			}

			// 绑定 IPv4 的源 IP
			var sa syscall.SockaddrInet4
			copy(sa.Addr[:], ip.To4())
			if err := syscall.Bind(fd, &sa); err != nil {
				retErr = os.NewSyscallError("bind", err)
				return nil, retErr
			}

		case syscall.AF_INET6:
			// 绑定接口（IPv6）
			if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_BOUND_IF, ifIndex); err != nil {
				retErr = os.NewSyscallError("setsockopt(IPV6_BOUND_IF)", err)
				return nil, retErr
			}

			// 绑定 IPv6 的源 IP
			var sa6 syscall.SockaddrInet6
			copy(sa6.Addr[:], ip.To16())
			sa6.ZoneId = uint32(ifIndex)
			if err := syscall.Bind(fd, &sa6); err != nil {
				retErr = os.NewSyscallError("bind", err)
				return nil, retErr
			}
		}
	}

	// 交由 net 层接管 fd，获得可与 poller 协作的 PacketConn
	file := os.NewFile(uintptr(fd), "icmp-dgram")
	pc, err := net.FilePacketConn(file)
	_ = file.Close()
	if err != nil {
		retErr = err
		return nil, retErr
	}
	retErr = nil
	return pc, nil
}
