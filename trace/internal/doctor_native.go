//go:build !(windows && amd64)

package internal

import "context"

func CheckProbeBackend(ctx context.Context, o BackendOptions) []BackendCheck {
	switch o.Protocol {
	case "tcp":
		s := NewTCPSpec(o.IPVersion, o.ICMPMode, o.Source, o.Target, o.Port, 0)
		s.SourceDevice = o.Device
		defer s.Close()
		checks := []BackendCheck{
			backendStep(ctx, "icmp_socket", s.InitICMP),
			backendStep(ctx, "tcp_socket_bind", s.InitTCP),
		}
		return append(checks, checkTCPCapture(ctx, s)...)
	case "udp":
		s := NewUDPSpec(o.IPVersion, o.ICMPMode, o.Source, o.Target, o.Port)
		s.SourceDevice = o.Device
		defer s.Close()
		checks := []BackendCheck{
			backendStep(ctx, "icmp_socket", s.InitICMP),
			backendStep(ctx, "udp_socket_bind", s.InitUDP),
		}
		return append(checks, checkUDPCapture(ctx, s)...)
	default:
		s := NewICMPSpec(o.IPVersion, o.ICMPMode, 1, o.Source, o.Target)
		s.SourceDevice = o.Device
		defer s.Close()
		return []BackendCheck{backendStep(ctx, "icmp_socket_bind", s.InitICMP)}
	}
}
