package trace

import (
	"fmt"
	"net"
	"runtime"
	"strings"

	"github.com/nxtrace/NTrace-core/util"
)

func ValidateFWMarkPlatform(explicit bool) error {
	if explicit && runtime.GOOS != "linux" {
		return fmt.Errorf("fwmark is supported only on Linux (excluding Android); current platform: %s", runtime.GOOS)
	}
	return nil
}

// PrepareFWMarkConfig resolves a marked session without the legacy process-wide
// source cache. Source/device constraints and the selected address stay local.
func PrepareFWMarkConfig(method Method, cfg Config) (Config, error) {
	if !cfg.FWMarkSet {
		return cfg, nil
	}
	if err := ValidateFWMarkPlatform(true); err != nil {
		return cfg, wrapProbeSetupError(err)
	}
	cfg.SrcAddr, cfg.SourceDevice = strings.TrimSpace(cfg.SrcAddr), strings.TrimSpace(cfg.SourceDevice)
	if cfg.DstIP == nil {
		return cfg, wrapProbeSetupError(fmt.Errorf("fwmark: invalid target IP"))
	}
	if _, err := ResolveSourceDevice(cfg.SourceDevice); err != nil {
		return cfg, wrapProbeSetupError(err)
	}
	if cfg.SrcAddr == "" {
		src, err := resolveFWMarkSource(method, cfg)
		if err != nil {
			return cfg, wrapProbeSetupError(fmt.Errorf("resolve source for fwmark %#x: %w", cfg.FWMark, err))
		}
		cfg.SrcAddr = src
	}
	ip := net.ParseIP(cfg.SrcAddr)
	if ip == nil || ip.IsUnspecified() || (ip.To4() == nil) != (cfg.DstIP.To4() == nil) {
		return cfg, wrapProbeSetupError(fmt.Errorf("fwmark source must be a usable IP matching the target family"))
	}
	if method != ICMPTrace && cfg.SrcPort == 0 && !probeRandomPortEnabled(cfg) {
		proto := string(method)
		if ip.To4() == nil {
			proto += "6"
		}
		_, port := probeLocalIPPort(cfg, ip, proto)
		if port <= 0 {
			return cfg, wrapProbeSetupError(fmt.Errorf("fwmark: cannot allocate source port"))
		}
		cfg.SrcPort = port
	}
	return cfg, nil
}

func resolveProbeSource(method Method, cfg *Config, source net.IP) (net.IP, error) {
	if cfg.FWMarkSet {
		prepared, err := PrepareFWMarkConfig(method, *cfg)
		if err != nil {
			return nil, err
		}
		*cfg = prepared
		return net.ParseIP(cfg.SrcAddr), nil
	}
	proto := string(method)
	if cfg.DstIP.To4() == nil {
		proto += "6"
	}
	ip, _ := probeLocalIPPort(*cfg, source, proto)
	return ip, nil
}

// Marked sessions only use these sockets for local port allocation: no connect
// or traffic, no mark, and no access to the legacy source/port cache.
func probeLocalIPPort(cfg Config, source net.IP, proto string) (net.IP, int) {
	if !cfg.FWMarkSet {
		if cfg.DstIP.To4() == nil {
			return util.LocalIPPortv6(cfg.DstIP, source, proto)
		}
		return util.LocalIPPort(cfg.DstIP, source, proto)
	}
	if strings.HasPrefix(proto, "tcp") {
		conn, err := net.ListenTCP(proto, &net.TCPAddr{IP: source})
		if err != nil {
			return nil, -1
		}
		defer func() { _ = conn.Close() }()
		return source, conn.Addr().(*net.TCPAddr).Port
	}
	conn, err := net.ListenUDP(proto, &net.UDPAddr{IP: source})
	if err != nil {
		return nil, -1
	}
	defer func() { _ = conn.Close() }()
	return source, conn.LocalAddr().(*net.UDPAddr).Port
}

// Marked sessions derive random-port selection from their own configuration.
func probeRandomPortEnabled(cfg Config) bool {
	if cfg.FWMarkSet {
		return util.EnvRandomPort || cfg.SrcPort == -1
	}
	return util.RandomPortEnabled()
}
