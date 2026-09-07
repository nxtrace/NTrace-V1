//go:build windows && amd64

package internal

import (
	"context"
	"errors"
	"fmt"

	wd "github.com/xjasonlyu/windivert-go"
	"golang.org/x/sys/windows"
)

func doctorWinStep(ctx context.Context, name string, fn func() error) BackendCheck {
	c := backendStep(ctx, name, fn)
	var err wd.Error
	if errors.As(c.Err, &err) && err == wd.Error(windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		c.Unknown = true
		c.Err = fmt.Errorf("NO_INSTALL: driver not installed; normal initialization was not attempted: %w", c.Err)
	}
	return c
}

func checkWinCapture(ctx context.Context, name, filter string) BackendCheck {
	return doctorWinStep(ctx, name, func() error {
		h, err := openWinDivertSniffWithFlags(filter, "doctor", wd.FlagNoInstall)
		if err == nil {
			_ = h.Close()
		}
		return err
	})
}

func checkWinICMPReceiver(ctx context.Context, o BackendOptions) []BackendCheck {
	if ctx.Err() != nil {
		return []BackendCheck{{Name: "receiver_selection", Err: ctx.Err(), Skipped: true}}
	}
	if o.ICMPMode == 1 {
		return []BackendCheck{{Name: "receiver_selection", Detail: "Socket"}}
	}
	if o.Protocol == "icmp" && !hasWindowsAdminPrivileges() {
		return []BackendCheck{{Name: "receiver_selection", Detail: "Socket; WinDivert selection requires administrator privileges"}}
	}
	c := doctorWinStep(ctx, "windivert_availability", func() error {
		_, err := winDivertAvailableWithFlags(wd.FlagNoInstall)
		return err
	})
	if c.Err != nil {
		// Normal listeners fall back to their already checked Socket receiver.
		// NO_INSTALL cannot predict whether normal execution would install first.
		c.Optional = !c.Unknown
		detail := "Socket; WinDivert availability check failed"
		if c.Unknown {
			detail = "Socket alternative checked; normal selection unverified under NO_INSTALL"
		}
		return []BackendCheck{c, {Name: "receiver_selection", Detail: detail}}
	}
	return []BackendCheck{c, {Name: "receiver_selection", Detail: "WinDivert"}, checkWinCapture(ctx, "windivert_icmp_filter", winDivertICMPFilter(o.IPVersion, o.Source))}
}

func CheckProbeBackend(ctx context.Context, o BackendOptions) []BackendCheck {
	var checks []BackendCheck
	switch o.Protocol {
	case "tcp":
		s := NewTCPSpec(o.IPVersion, o.ICMPMode, o.Source, o.Target, o.Port, 0)
		s.SourceDevice = o.Device
		defer s.Close()
		checks = append(checks, backendStep(ctx, "icmp_socket", s.InitICMP),
			doctorWinStep(ctx, "windivert_tcp_send", func() error { return s.initTCP(wd.FlagNoInstall) }),
			checkWinCapture(ctx, "windivert_tcp_filter", winDivertTCPFilter(o.IPVersion, o.Source, o.Port)))
	case "udp":
		s := NewUDPSpec(o.IPVersion, o.ICMPMode, o.Source, o.Target, o.Port)
		s.SourceDevice = o.Device
		defer s.Close()
		checks = append(checks, backendStep(ctx, "icmp_socket", s.InitICMP),
			doctorWinStep(ctx, "windivert_udp_send", func() error { return s.initUDP(wd.FlagNoInstall) }))
	default:
		s := NewICMPSpec(o.IPVersion, o.ICMPMode, 1, o.Source, o.Target)
		s.SourceDevice = o.Device
		defer s.Close()
		checks = append(checks, backendStep(ctx, "icmp_socket_bind", s.InitICMP))
		if o.IPVersion == 6 && o.TOS != 0 {
			checks = append(checks, doctorWinStep(ctx, "windivert_icmp_send", func() error {
				return s.ensureICMPSendHandleWithFlags(true, wd.FlagNoInstall)
			}))
		}
	}
	return append(checks, checkWinICMPReceiver(ctx, o)...)
}
