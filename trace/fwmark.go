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

// PrepareFWMarkConfig preserves the marked-session preparation entry point.
func PrepareFWMarkConfig(method Method, cfg Config) (Config, error) {
	if !cfg.FWMarkSet {
		return cfg, nil
	}
	return PrepareProbeSourceConfig(method, cfg)
}

func usesPolicyRouteSource(cfg Config) bool {
	return cfg.FWMarkSet || (runtime.GOOS == "linux" && cfg.TOS != 0)
}

// PrepareProbeSourceConfig resolves Linux TOS/marked sessions without the legacy
// process-wide source cache. Source/device constraints stay local to the session.
// Other platforms retain their native source-selection behavior for TOS.
func PrepareProbeSourceConfig(method Method, cfg Config) (Config, error) {
	if !usesPolicyRouteSource(cfg) {
		return cfg, nil
	}
	if err := ValidateFWMarkPlatform(cfg.FWMarkSet); err != nil {
		return cfg, wrapProbeSetupError(err)
	}
	cfg.SrcAddr, cfg.SourceDevice = strings.TrimSpace(cfg.SrcAddr), strings.TrimSpace(cfg.SourceDevice)
	if cfg.DstIP == nil {
		return cfg, wrapProbeSetupError(fmt.Errorf("probe route: invalid target IP"))
	}
	if _, err := ResolveSourceDevice(cfg.SourceDevice); err != nil {
		return cfg, wrapProbeSetupError(err)
	}

	if cfg.SrcAddr == "" {
		src, err := resolveProbeRouteSource(method, cfg)
		if err != nil {
			conditions := fmt.Sprintf("TOS %#x", cfg.TOS)
			if cfg.FWMarkSet {
				conditions += fmt.Sprintf(", fwmark %#x", cfg.FWMark)
			}
			return cfg, wrapProbeSetupError(fmt.Errorf("resolve probe source for %s: %w", conditions, err))
		}
		cfg.SrcAddr = src
	}
	ip := net.ParseIP(cfg.SrcAddr)
	if ip == nil || ip.IsUnspecified() || (ip.To4() == nil) != (cfg.DstIP.To4() == nil) {
		return cfg, wrapProbeSetupError(fmt.Errorf("probe route source must be a usable IP matching the target family"))
	}
	if method != ICMPTrace && cfg.SrcPort == 0 && !probeRandomPortEnabled(cfg) {
		proto := string(method)
		if cfg.DstIP.To4() == nil {
			proto += "6"
		} else {
			proto += "4"
		}
		_, port := probeLocalIPPort(cfg, ip, proto)
		if port <= 0 {
			return cfg, wrapProbeSetupError(fmt.Errorf("probe route: cannot allocate source port"))
		}
		cfg.SrcPort = port
	}
	return cfg, nil
}

func resolveProbeSource(method Method, cfg *Config, source net.IP) (net.IP, error) {
	if usesPolicyRouteSource(*cfg) {
		prepared, err := PrepareProbeSourceConfig(method, *cfg)
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

// Policy-routed sessions only use these sockets for local port allocation: no
// connect or traffic, and no access to the legacy source/port cache.
func probeLocalIPPort(cfg Config, source net.IP, proto string) (net.IP, int) {
	if !usesPolicyRouteSource(cfg) {
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

// Policy-routed sessions derive random-port selection from their own configuration.
func probeRandomPortEnabled(cfg Config) bool {
	if usesPolicyRouteSource(cfg) {
		return util.EnvRandomPort || cfg.SrcPort == -1
	}
	return util.RandomPortEnabled()
}
